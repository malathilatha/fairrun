"""Zero-knowledge Proof of Segregated Funds (DAPOL+-style, demo version).

The plain Merkle sum tree (`solvency.py`) has one leak: an employer's proof shows its siblings' SUMS,
so with few employers Alpha can work out Bright's balance. This version hides them.

- Every amount in the tree is a Pedersen commitment  C = v*G + r*H  on secp256k1.
  It hides v completely (r is random) and binds the platform to v (it cannot open C to another value).
- Commitments add up: C_left + C_right commits to v_left + v_right. A parent's commitment is just the sum
  of its children's, so the tree still adds up, without anyone seeing the numbers.
- Every node an employer is shown comes with a ZERO-KNOWLEDGE RANGE PROOF that its hidden amount is in
  [0, 2^40). That is what stops a negative "hole" hiding liabilities (theorem T1 in solvency.py).
  The range proof is the classic bit-decomposition construction: one commitment per bit plus a
  Chaum-Damgard-Schoenmakers OR-proof that each bit is 0 or 1, made non-interactive with Fiat-Shamir.
- The platform reveals only the TOTAL per currency (and the total blinding), signed with the hybrid
  Ed25519 + ML-DSA signer. Each employer opens only its own leaf.

What an employer learns: its own balance is inside the signed total and every other part of the
tree is non-negative. What it does NOT learn: any other employer's balance, name or currencies held.

References: Ji & Chalkias, "Generalized Proof of Liabilities" (ACM CCS 2021, DAPOL+);
Bunz et al., "Bulletproofs" (IEEE S&P 2018), which would shrink each range proof from ~10 KB to ~0.7 KB.
Honest limits: demo-grade pure-Python curve code (not constant-time); a snapshot at one moment; the
platform still learns everything (it is the prover); the number of leaves is visible.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import secrets
import time

from . import ec
from .crypto import HybridSigner, verify_signature
from .models import to_major
from .solvency import FundsBook, check_segregation, pooled_check

SCHEME = "pedersen-secp256k1/bit-range-40/v1"
BITS = 40                       # each node < 2^40 minor units (~11 billion in major units)
CH = 2 ** 128                   # challenge space


def commit(v: int, r: int):
    return ec.add(ec.G_FB.mul(v), ec.H_FB.mul(r))


def _hx(pt) -> str:
    return ec.encode(pt).hex()


def _challenge(*parts) -> int:
    h = hashlib.sha256(b"FairRun-zk-range|" + SCHEME.encode())
    for p in parts:
        b = p if isinstance(p, bytes) else str(p).encode()
        h.update(len(b).to_bytes(4, "big") + b)
    return int.from_bytes(h.digest(), "big") % CH


# ---------------------------------------------------------------------------
# Range proof: C commits to v with 0 <= v < 2^BITS, revealing nothing else
# ---------------------------------------------------------------------------
def range_prove(v: int, r: int, context: str) -> dict:
    if not 0 <= v < 2 ** BITS:
        raise ValueError("amount out of range: no valid proof exists")
    C = commit(v, r)
    s = [secrets.randbelow(ec.N) for _ in range(BITS)]
    s[0] = (r - sum((1 << i) * s[i] for i in range(1, BITS))) % ec.N   # bit blindings add up to r
    neg_g = ec.neg(ec.G)
    bits = []
    for i in range(BITS):
        b = (v >> i) & 1
        B = commit(b, s[i])
        Y = [B, ec.add(B, neg_g)]                  # B = s*H if bit is 0;  B - G = s*H if bit is 1
        sim = 1 - b
        c_sim, z_sim, w = secrets.randbelow(CH), secrets.randbelow(ec.N), secrets.randbelow(ec.N)
        a = [None, None]
        a[b] = ec.H_FB.mul(w)
        a[sim] = ec.add(ec.H_FB.mul(z_sim), ec.neg(ec.mul(Y[sim], c_sim)))   # simulated branch
        c = _challenge(context, ec.encode(C), i, ec.encode(B), ec.encode(a[0]), ec.encode(a[1]))
        c_real = (c - c_sim) % CH
        z_real = (w + c_real * s[i]) % ec.N
        cs, zs = [0, 0], [0, 0]
        cs[b], cs[sim], zs[b], zs[sim] = c_real, c_sim, z_real, z_sim
        bits.append([_hx(B), f"{cs[0]:x}", f"{cs[1]:x}", f"{zs[0]:x}", f"{zs[1]:x}"])
    return {"C": _hx(C), "bits": bits}


def range_verify(proof: dict, context: str) -> bool:
    try:
        C = ec.decode(bytes.fromhex(proof["C"]))
        if len(proof["bits"]) != BITS:
            return False
        neg_g = ec.neg(ec.G)
        Bs = []
        for i, (bh, c0, c1, z0, z1) in enumerate(proof["bits"]):
            B = ec.decode(bytes.fromhex(bh))       # decode checks the point is on the curve
            c0, c1, z0, z1 = int(c0, 16), int(c1, 16), int(z0, 16), int(z1, 16)
            if c0 >= CH or c1 >= CH:
                return False
            Y0, Y1 = B, ec.add(B, neg_g)
            a0 = ec.add(ec.H_FB.mul(z0), ec.neg(ec.mul(Y0, c0)))
            a1 = ec.add(ec.H_FB.mul(z1), ec.neg(ec.mul(Y1, c1)))
            c = _challenge(context, ec.encode(C), i, ec.encode(B), ec.encode(a0), ec.encode(a1))
            if (c0 + c1) % CH != c:
                return False
            Bs.append(B)
        acc = ec.INF                                # sum 2^i * B_i must equal C
        for B in reversed(Bs):
            acc = ec.add(ec.add(acc, acc), B)
        return acc == C
    except (ValueError, KeyError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Tree of commitments
# ---------------------------------------------------------------------------
def _leaf_hash(tag: str, salt: str, comms: dict) -> str:
    h = hashlib.sha256(b"\x00" + tag.encode() + b"|" + bytes.fromhex(salt))
    for c in sorted(comms):
        h.update(c.encode() + bytes.fromhex(comms[c]))
    return h.hexdigest()


def _node_hash(lh: str, lc: dict, rh: str, rc: dict) -> str:
    h = hashlib.sha256(b"\x01" + bytes.fromhex(lh) + bytes.fromhex(rh))
    for c in sorted(lc):
        h.update(c.encode() + bytes.fromhex(lc[c]) + bytes.fromhex(rc[c]))
    return h.hexdigest()


class ZkSolvencyProver:
    def __init__(self, signer: HybridSigner | None = None):
        self.signer = signer or HybridSigner.generate()
        self.public_keys = {self.signer.alg: self.signer.public()}

    def prove(self, book: FundsBook, client) -> dict:
        started = time.time()
        held = {e: client.get_balances(e) for e in book.owed}
        currencies = sorted({c for cur in book.owed.values() for c in cur})
        order = list(book.owed)
        random.SystemRandom().shuffle(order)

        # leaves: every employer commits to EVERY currency (0 if none), so holdings don't leak
        leaves = []
        for e in order:
            vals = {c: book.owed[e].get(c, 0) for c in currencies}
            if any(v < 0 for v in vals.values()):
                raise ValueError(f"books show a negative balance for {e}")
            leaves.append({"tag": e, "salt": os.urandom(16).hex(), "v": vals,
                           "r": {c: secrets.randbelow(ec.N) for c in currencies}})
        while len(leaves) & (len(leaves) - 1):              # padding leaves look like real ones
            leaves.append({"tag": "pad-" + os.urandom(8).hex(), "salt": os.urandom(16).hex(),
                           "v": {c: 0 for c in currencies}, "r": {c: secrets.randbelow(ec.N) for c in currencies}})
        for lf in leaves:
            lf["C"] = {c: _hx(commit(lf["v"][c], lf["r"][c])) for c in currencies}
            lf["hash"] = _leaf_hash(lf["tag"], lf["salt"], lf["C"])

        levels = [leaves]
        while len(levels[-1]) > 1:
            cur, nxt = levels[-1], []
            for i in range(0, len(cur), 2):
                L, R = cur[i], cur[i + 1]
                node = {"v": {c: L["v"][c] + R["v"][c] for c in currencies},
                        "r": {c: (L["r"][c] + R["r"][c]) % ec.N for c in currencies},
                        "C": {c: _hx(ec.add(ec.decode(bytes.fromhex(L["C"][c])),
                                            ec.decode(bytes.fromhex(R["C"][c])))) for c in currencies}}
                node["hash"] = _node_hash(L["hash"], L["C"], R["hash"], R["C"])
                nxt.append(node)
            levels.append(nxt)
        for level in levels[:-1]:                          # range proofs for every non-root node
            for node in level:
                node["range"] = {c: range_prove(node["v"][c], node["r"][c], c) for c in currencies}

        root = levels[-1][0]
        ok, breaches = check_segregation(book.owed, held)
        statement = {"scheme": SCHEME, "as_of": round(time.time(), 3), "root": root["hash"],
                     "currencies": currencies, "leaves": len(leaves),
                     "owed_total": root["v"], "total_blinding": {c: f"{root['r'][c]:x}" for c in currencies},
                     "segregated": ok, "breaches": len(breaches)}
        sig = self.signer.sign(json.dumps(statement, sort_keys=True).encode())
        return {"statement": statement, "signatures": [sig], "breaches": breaches,
                "pooled_ok": pooled_check(book.owed, held), "seconds": round(time.time() - started, 2),
                "_levels": levels, "_order": order}

    @staticmethod
    def inclusion_proof(proof: dict, employer: str) -> dict:
        idx = proof["_order"].index(employer)
        leaf = proof["_levels"][0][idx]
        path = []
        for level in proof["_levels"][:-1]:
            sib = level[idx ^ 1]
            path.append({"side": "L" if (idx ^ 1) < idx else "R", "hash": sib["hash"],
                         "C": sib["C"], "range": sib["range"]})
            idx //= 2
        return {"employer": employer, "salt": leaf["salt"], "owed": dict(leaf["v"]),
                "blinding": {c: f"{r:x}" for c, r in leaf["r"].items()},
                "path": path, "statement": proof["statement"], "signatures": proof["signatures"]}


def verify_zk_inclusion(p: dict, public_keys: dict, my_live_balance: dict | None = None) -> tuple[bool, str]:
    """Run by ONE employer with only its own proof: learns nothing about any other employer."""
    st = p["statement"]
    msg = json.dumps(st, sort_keys=True).encode()
    good = [s["alg"] for s in p["signatures"]
            if s["alg"] in public_keys and verify_signature(public_keys[s["alg"]], msg, s)]
    if not good:
        return False, "statement signature invalid"
    if st.get("scheme") != SCHEME:
        return False, "unknown proof scheme"
    cur = st["currencies"]
    try:
        mine = {c: commit(p["owed"][c], int(p["blinding"][c], 16)) for c in cur}
    except KeyError:
        return False, "proof does not cover every currency"
    if any(not 0 <= p["owed"][c] < 2 ** BITS for c in cur):
        return False, "my amount is out of range"
    h = _leaf_hash(p["employer"], p["salt"], {c: _hx(mine[c]) for c in cur})
    acc = mine
    for step in p["path"]:
        for c in cur:
            if step["range"][c]["C"] != step["C"][c] or not range_verify(step["range"][c], c):
                return False, f"a hidden part of the tree has no valid non-negative proof ({c})"
        sib = {c: ec.decode(bytes.fromhex(step["C"][c])) for c in cur}
        mine_hex = {c: _hx(acc[c]) for c in cur}
        if step["side"] == "L":
            h = _node_hash(step["hash"], step["C"], h, mine_hex)
        else:
            h = _node_hash(h, mine_hex, step["hash"], step["C"])
        acc = {c: ec.add(acc[c], sib[c]) for c in cur}
    if h != st["root"]:
        return False, "my balance is not in the signed tree"
    for c in cur:
        if acc[c] != commit(st["owed_total"][c], int(st["total_blinding"][c], 16)):
            return False, f"signed {c} total does not match the tree"
    if my_live_balance is not None:
        short = {c: v - my_live_balance.get(c, 0) for c, v in p["owed"].items()
                 if v and my_live_balance.get(c, 0) < v}
        if short:
            return False, "my own account holds less than I am owed: short " + ", ".join(
                f"{to_major(v)} {c}" for c, v in short.items())
    return True, f"included in signed total, others hidden; own account covers it ({', '.join(good)})"
