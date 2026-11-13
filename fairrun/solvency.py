"""Proof of Segregated Funds: every employer can check that ITS money is really held in ITS own account.

Crypto exchanges publish "proof of reserves": a Merkle sum tree over customer balances, showing
total assets >= total liabilities. That check is too weak for payroll. A platform can pass it while
quietly covering one employer's hole with another employer's money, because the TOTAL stays the
same. That is exactly how commingling failures happen.

FairRun proves the stronger, per-employer statement, for every employer e and currency c:

    held(e, c) >= owed(e, c)        held = live balance of e's own Airwallex connected account
                                    owed = what FairRun's books say e has with the platform

How it works
1. Liabilities (owed) go into a Merkle SUM tree. Each node hashes BOTH children's hashes AND
   BOTH children's sums, and every sum must be non-negative. (Early designs hashed only the parent
   total, which lets an operator hide liabilities; see Chalkias, Chatzigiannis, Ji 2022.)
   Leaves are salted and shuffled, so a proof does not say which sibling belongs to whom.
2. Z3 checks the segregation rule R5 for every (employer, currency) and names every breach.
3. The statement (root, totals, result, time) is signed once with the hybrid Ed25519 + ML-DSA signer.
4. Each employer gets an inclusion proof. It verifies offline that its balance is in the signed
   root, then compares the amount to the balance it sees in its OWN Airwallex dashboard.

Two theorems are checked with Z3 (see `prove_lemmas`), not just tested on examples:
  T1  With non-negative node sums, every included leaf <= the root total: the platform cannot
      show an employer a balance that is not counted. Without the check, a counterexample exists.
  T2  Per-employer segregation implies total solvency, but NOT the other way round: Z3 produces a
      case where totals balance while one employer is short. This is why total-only proofs miss it.

Honest limits: the proof is a snapshot at one moment; sibling sums in a proof reveal partial
totals (not whose); production would use commitments + range proofs (e.g. DAPOL+) to hide them.
In production the books are kept from FairRun's ledger and Airwallex deposit webhooks.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import time

import z3

from .crypto import HybridSigner, verify_signature
from .models import to_major


# ---------------------------------------------------------------------------
# FairRun's books: what each employer has with the platform, per currency
# ---------------------------------------------------------------------------
class FundsBook:
    def __init__(self):
        self.owed: dict[str, dict[str, int]] = {}

    @classmethod
    def snapshot(cls, client, accounts) -> "FundsBook":
        """Start the books from reconciled balances (after FairRun's own runs)."""
        book = cls()
        for a in accounts:
            book.owed[a] = {c: v for c, v in client.get_balances(a).items() if v}
        return book

    def credit(self, account: str, currency: str, amount: int) -> None:
        cur = self.owed.setdefault(account, {})
        cur[currency] = cur.get(currency, 0) + amount

    def debit(self, account: str, currency: str, amount: int) -> None:
        self.credit(account, currency, -amount)


# ---------------------------------------------------------------------------
# Merkle sum tree
# ---------------------------------------------------------------------------
def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _enc(sums: dict) -> bytes:
    return json.dumps({k: v for k, v in sorted(sums.items()) if v}, sort_keys=True).encode()


def _add(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + v
    return {k: v for k, v in out.items() if v}


def _negative(sums: dict) -> bool:
    return any(v < 0 for v in sums.values())


def leaf_hash(employer: str, salt: str, sums: dict) -> str:
    return _h(b"\x00" + employer.encode() + b"|" + bytes.fromhex(salt) + b"|" + _enc(sums))


def node_hash(lh: str, ls: dict, rh: str, rs: dict) -> str:
    # both child hashes AND both child sums are bound into the parent
    return _h(b"\x01" + bytes.fromhex(lh) + _enc(ls) + bytes.fromhex(rh) + _enc(rs))


def build_tree(leaves: list[tuple[str, dict]]) -> list[list[tuple[str, dict]]]:
    """leaves: [(hash, sums)], padded to a power of two. Returns levels, root last."""
    level = list(leaves)
    while len(level) & (len(level) - 1):
        level.append((_h(b"\x02" + os.urandom(32)), {}))          # zero-sum padding leaf
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            (lh, ls), (rh, rs) = level[i], level[i + 1]
            if _negative(ls) or _negative(rs):
                raise ValueError("negative sum in tree")
            nxt.append((node_hash(lh, ls, rh, rs), _add(ls, rs)))
        level = nxt
        levels.append(level)
    return levels


# ---------------------------------------------------------------------------
# Z3: the segregation rule and the two lemmas
# ---------------------------------------------------------------------------
def check_segregation(owed: dict, held: dict) -> tuple[bool, list[str]]:
    """R5_segregated: for EVERY employer and currency, held >= owed (own account only)."""
    s = z3.Solver()
    names = []
    for e, cur in owed.items():
        for c, amount in cur.items():
            o, h = z3.Int(f"owed_{e}_{c}"), z3.Int(f"held_{e}_{c}")
            s.add(o == amount, h == held.get(e, {}).get(c, 0))
            tag = f"{e}:{c}"
            names.append(tag)
            s.assert_and_track(h >= o, tag)
    if s.check() == z3.sat:
        return True, []
    breaches = []
    for tag in names:                      # report every breach, not only the first core
        e, c = tag.split(":")
        single = z3.Solver()
        single.add(z3.Int(f"held_{e}_{c}") == held.get(e, {}).get(c, 0),
                   z3.Int(f"owed_{e}_{c}") == owed[e][c],
                   z3.Int(f"held_{e}_{c}") >= z3.Int(f"owed_{e}_{c}"))
        if single.check() == z3.unsat:
            breaches.append(tag)
    return False, breaches


def pooled_check(owed: dict, held: dict) -> bool:
    """What a total-only proof of reserves checks: sum held >= sum owed, per currency."""
    tot_o, tot_h = {}, {}
    for cur in owed.values():
        tot_o = _add(tot_o, cur)
    for e in owed:
        tot_h = _add(tot_h, held.get(e, {}))
    return all(tot_h.get(c, 0) >= v for c, v in tot_o.items())


def prove_lemmas(depth: int = 3, employers: int = 3) -> dict:
    """Prove T1 and T2 for ALL values (symbolic integers), not for one example."""
    n = 2 ** depth
    leaves = [z3.Int(f"leaf_{i}") for i in range(n)]
    level = leaves
    while len(level) > 1:
        level = [level[i] + level[i + 1] for i in range(0, len(level), 2)]
    root = level[0]

    # T1 with the non-negativity check: no assignment makes an included leaf exceed the root.
    s = z3.Solver()
    s.add(*[x >= 0 for x in leaves], z3.Or(*[x > root for x in leaves]))
    t1 = s.check() == z3.unsat

    # T1 without the check: Z3 finds the attack (a negative leaf hides real liabilities).
    s = z3.Solver()
    s.add(leaves[0] == 5000, root == 0, *[x == 0 for x in leaves[2:]])   # hide a 5,000 liability
    attack = None
    if s.check() == z3.sat:
        m = s.model()
        attack = {"leaves": [m.eval(x).as_long() for x in leaves], "root": m.eval(root).as_long()}

    # T2: segregated => solvent (always), solvent =/=> segregated (counterexample).
    held = [z3.Int(f"h{i}") for i in range(employers)]
    owed = [z3.Int(f"o{i}") for i in range(employers)]
    base = [x >= 0 for x in held + owed]
    s = z3.Solver()
    s.add(*base, *[h >= o for h, o in zip(held, owed)], z3.Sum(held) < z3.Sum(owed))
    t2_forward = s.check() == z3.unsat
    s = z3.Solver()
    s.add(*base, *[o >= 1000 for o in owed], z3.Sum(held) >= z3.Sum(owed),
          z3.Or(*[h < o for h, o in zip(held, owed)]))
    gap = None
    if s.check() == z3.sat:
        m = s.model()
        gap = {"held": [m.eval(x).as_long() for x in held], "owed": [m.eval(x).as_long() for x in owed]}
    return {"T1_leaf_le_root": t1, "T1_attack_without_check": attack,
            "T2_segregated_implies_solvent": t2_forward, "T2_solvent_not_segregated_example": gap}


# ---------------------------------------------------------------------------
# Prover (platform side) and verifier (employer side)
# ---------------------------------------------------------------------------
class SolvencyProver:
    def __init__(self, signer: HybridSigner | None = None):
        self.signer = signer or HybridSigner.generate()
        self.public_keys = {self.signer.alg: self.signer.public()}

    def prove(self, book: FundsBook, client) -> dict:
        held = {e: client.get_balances(e) for e in book.owed}       # live, each employer's own account
        for e, cur in book.owed.items():
            if _negative(cur):
                raise ValueError(f"books show a negative balance for {e}")
        salts = {e: os.urandom(16).hex() for e in book.owed}
        order = list(book.owed)
        random.SystemRandom().shuffle(order)                        # position says nothing about who
        levels = build_tree([(leaf_hash(e, salts[e], book.owed[e]), book.owed[e]) for e in order])
        root, owed_total = levels[-1][0]
        ok, breaches = check_segregation(book.owed, held)
        held_total = {}
        for e in book.owed:
            held_total = _add(held_total, held[e])
        statement = {"as_of": round(time.time(), 3), "root": root, "owed_total": owed_total,
                     "held_total": held_total, "employers": len(order), "segregated": ok,
                     "breaches": len(breaches)}
        sig = self.signer.sign(json.dumps(statement, sort_keys=True).encode())
        return {"statement": statement, "signatures": [sig], "breaches": breaches,
                "pooled_ok": pooled_check(book.owed, held),
                "_levels": levels, "_order": order, "_salts": salts, "_owed": book.owed}

    @staticmethod
    def inclusion_proof(proof: dict, employer: str) -> dict:
        """Private to one employer: its leaf + sibling hashes/sums. No names of other employers."""
        idx = proof["_order"].index(employer)
        path = []
        for level in proof["_levels"][:-1]:
            sib = idx ^ 1
            h, s = level[sib]
            path.append({"side": "L" if sib < idx else "R", "hash": h, "sums": s})
            idx //= 2
        return {"employer": employer, "salt": proof["_salts"][employer], "owed": proof["_owed"][employer],
                "path": path, "statement": proof["statement"], "signatures": proof["signatures"]}


def verify_inclusion(p: dict, public_keys: dict, my_live_balance: dict | None = None) -> tuple[bool, str]:
    """What an employer runs, offline, with only its own proof and the platform's public key."""
    st = p["statement"]
    msg = json.dumps(st, sort_keys=True).encode()
    good = [s["alg"] for s in p["signatures"]
            if s["alg"] in public_keys and verify_signature(public_keys[s["alg"]], msg, s)]
    if not good:
        return False, "statement signature invalid"
    h, sums = leaf_hash(p["employer"], p["salt"], p["owed"]), dict(p["owed"])
    if _negative(sums):
        return False, "negative leaf"
    for step in p["path"]:
        if _negative(step["sums"]):
            return False, "negative sibling sum: liabilities could be hidden"
        if step["side"] == "L":
            h, sums = node_hash(step["hash"], step["sums"], h, sums), _add(step["sums"], sums)
        else:
            h, sums = node_hash(h, sums, step["hash"], step["sums"]), _add(sums, step["sums"])
    if h != st["root"] or sums != st["owed_total"]:
        return False, "my balance is not in the signed total"
    if my_live_balance is not None:
        short = {c: v - my_live_balance.get(c, 0) for c, v in p["owed"].items() if my_live_balance.get(c, 0) < v}
        if short:
            return False, "my own account holds less than I am owed: short " + ", ".join(
                f"{to_major(v)} {c}" for c, v in short.items())
    return True, f"included in signed total; own account covers it ({', '.join(good)})"
