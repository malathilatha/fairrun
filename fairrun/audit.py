"""Sealed audit log with private per-employer receipts.

After a run, every new log entry hash becomes a leaf of a Merkle tree. The tree's root is signed
ONCE with the hybrid Ed25519 + ML-DSA signer (one ~3.3 KB post-quantum signature per run, not per entry).

Each employer then gets a receipt: its own entries plus a short Merkle proof for each. Anyone holding
the receipt and the platform's public key can check the employer's history is in the signed log,
WITHOUT seeing other employers' entries (proofs contain only sibling hashes).
"""
from __future__ import annotations

import hashlib
import json

from .crypto import HybridSigner, verify_signature
from .ledger import entry_hash


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _leaf(entry_hash_hex: str) -> bytes:
    return _h(b"\x00" + bytes.fromhex(entry_hash_hex))         # domain-separated leaves


def _node(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = [_node(cur[i], cur[i + 1] if i + 1 < len(cur) else cur[i]) for i in range(0, len(cur), 2)]
        levels.append(nxt)
    return levels


def merkle_proof(levels: list[list[bytes]], index: int) -> list[tuple[str, str]]:
    proof = []
    for level in levels[:-1]:
        sib = index ^ 1
        sib_hash = level[sib] if sib < len(level) else level[index]
        proof.append(("L" if sib < index else "R", sib_hash.hex()))
        index //= 2
    return proof


def verify_proof(entry_hash_hex: str, proof: list, root_hex: str) -> bool:
    h = _leaf(entry_hash_hex)
    for side, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        h = _node(sib, h) if side == "L" else _node(h, sib)
    return h.hex() == root_hex


class AuditSealer:
    def __init__(self, ledger, signer: HybridSigner | None = None):
        self.ledger = ledger
        self.signer = signer or HybridSigner.generate()
        self.public_keys = {self.signer.alg: self.signer.public()}
        self.seals: list[dict] = []
        self._sealed_upto = 0

    def seal(self) -> dict:
        """Sign the Merkle root over every log entry written since the last seal."""
        rows = list(self.ledger.db.execute(
            "SELECT seq, employer, hash FROM log WHERE seq > ? ORDER BY seq", (self._sealed_upto,)))
        if not rows:
            raise ValueError("nothing new to seal")
        levels = merkle_levels([_leaf(h) for _, _, h in rows])
        root = levels[-1][0].hex()
        header = {"first_seq": rows[0][0], "last_seq": rows[-1][0], "entries": len(rows), "root": root}
        msg = json.dumps(header, sort_keys=True).encode()
        seal = {**header, "signatures": [self.signer.sign(msg)], "_rows": rows, "_levels": levels}
        self.seals.append(seal)
        self._sealed_upto = rows[-1][0]
        return seal

    def receipt(self, seal: dict, employer: str) -> dict:
        """Only this employer's entries, each with a Merkle proof. No other employer's data."""
        items = []
        for i, (seq, emp, h) in enumerate(seal["_rows"]):
            if emp == employer:
                ts, kind, body, prev = self.ledger.db.execute(
                    "SELECT ts, kind, body, prev_hash FROM log WHERE seq=?", (seq,)).fetchone()
                items.append({"seq": seq, "ts": ts, "kind": kind, "employer": emp, "body": json.loads(body),
                              "prev_hash": prev, "entry_hash": h, "proof": merkle_proof(seal["_levels"], i)})
        header = {k: seal[k] for k in ("first_seq", "last_seq", "entries", "root")}
        return {"employer": employer, "seal": header, "signatures": seal["signatures"], "items": items}

    def rotate_signer(self, new_alg: str) -> None:
        """Crypto-agility: add a signature under the new algorithm to every existing seal.
        Old signatures stay, so receipts issued earlier still verify with the old public key."""
        new = HybridSigner.generate(new_alg)
        for seal in self.seals:
            header = {k: seal[k] for k in ("first_seq", "last_seq", "entries", "root")}
            seal["signatures"].append(new.sign(json.dumps(header, sort_keys=True).encode()))
        self.signer = new
        self.public_keys[new.alg] = new.public()


def verify_receipt(receipt: dict, public_keys: dict) -> tuple[bool, str]:
    """What an employer (or auditor) runs: recompute each entry's hash from its content, check the
    Merkle proof against the signed root, and check the hybrid signature."""
    header = receipt["seal"]
    msg = json.dumps(header, sort_keys=True).encode()
    good = [s["alg"] for s in receipt["signatures"]
            if s["alg"] in public_keys and verify_signature(public_keys[s["alg"]], msg, s)]
    if not good:
        return False, "no valid signature on the seal"
    for item in receipt["items"]:
        h = entry_hash(item["ts"], item["kind"], item["employer"], item["body"], item["prev_hash"])
        if h != item["entry_hash"]:
            return False, f"entry {item['seq']} content does not match its hash"
        if not verify_proof(h, item["proof"], header["root"]):
            return False, f"entry {item['seq']} is not in the signed log"
    return True, f"{len(receipt['items'])} entries verified; signed with {', '.join(good)}"
