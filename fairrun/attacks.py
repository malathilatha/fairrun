"""'Try to cheat FairRun': four attacks a judge can launch, each against FairRun's real checks.

Every attack works on copies, so the main demo's money, ledger and proofs are never damaged.
"""
from __future__ import annotations

import copy
import dataclasses
import json

from . import ec
from .ledger import Ledger, entry_hash
from .crypto import HybridSigner
from .engine import FairRun
from .models import to_major, to_minor
from .pricing import price_plan
from .quantum_demo import forge_audit_seal, harvest_now_decrypt_later
from .verifier import verify
from .zk_solvency import commit, range_prove, range_verify, verify_zk_inclusion


def foreign_wallet(aw, thief, victim) -> dict:
    """Pay `thief` employer's workers from `victim` employer's wallet."""
    plan = price_plan(thief, "attack")
    plan.payouts = [dataclasses.replace(p, source_account=victim.employer_id) for p in plan.payouts]
    balance = aw.get_balances(thief.employer_id).get(thief.wallet_currency, 0)
    v = verify(plan, balance, set(), set())
    return {"caught": not v.ok, "rules": v.broken_rules, "detail": v.detail}


def edit_audit_log(ledger: Ledger) -> dict:
    """Change a recorded payment amount: once naively, once while also re-computing its hash."""
    work = Ledger()
    ledger.db.backup(work.db)                                      # attack a copy, never the real log
    rows = work.db.execute("SELECT seq,ts,kind,employer,body FROM log WHERE kind='intent' ORDER BY seq").fetchall()
    last_seq = work.db.execute("SELECT MAX(seq) FROM log").fetchone()[0]
    target = next((r for r in rows if r[0] != last_seq
                   and not json.loads(r[4]).get("contractor", "").startswith("fx:")), None)
    if target is None:
        return {"caught": None, "detail": "No recorded payments yet. Run situation 1 or 2 first."}
    seq, ts, kind, employer, body = target
    body = json.loads(body)
    old = body["amount"]
    body["amount"] = old * 10

    naive = Ledger()
    work.db.backup(naive.db)
    naive.db.execute("UPDATE log SET body=? WHERE seq=?", (json.dumps(body, sort_keys=True), seq))
    ok1, bad1 = naive.verify_chain()

    clever = Ledger()
    work.db.backup(clever.db)
    prev = clever.db.execute("SELECT prev_hash FROM log WHERE seq=?", (seq,)).fetchone()[0]
    clever.db.execute("UPDATE log SET body=?, hash=? WHERE seq=?",
                      (json.dumps(body, sort_keys=True), entry_hash(ts, kind, employer, body, prev), seq))
    ok2, bad2 = clever.verify_chain()

    cut = Ledger()                                                 # third try: quietly delete the newest entries
    work.db.backup(cut.db)
    total = cut.db.execute("SELECT COUNT(*) FROM log").fetchone()[0]
    head = cut.db.execute("SELECT hash FROM log ORDER BY seq DESC LIMIT 1").fetchone()[0]
    cut.db.execute("DELETE FROM log WHERE seq > ?", (last_seq - 3,))
    ok3, bad3 = cut.verify_chain(anchor=(total, head))
    return {"caught": (not ok1) and (not ok2) and (not ok3), "cut_flag": bad3, "seq": seq, "contractor": body.get("contractor"),
            "old": to_major(old), "new": to_major(old * 10), "currency": body.get("currency"),
            "naive_flag": bad1, "clever_flag": bad2}


def hide_money(prover, proof) -> dict:
    """Make the platform owe an employer less than it really does, or hide a debt with a negative entry."""
    employer_id, currency = next(((e, c) for e in proof["_order"] for c, v in proof["_levels"][0][
        proof["_order"].index(e)]["v"].items() if v >= 100), (None, None))
    if employer_id is None:
        return {"caught": None, "detail": "No employer holds money to hide. Reset the demo first."}
    p = prover.inclusion_proof(proof, employer_id)
    lower = copy.deepcopy(p)
    lower["owed"][currency] -= 100                                       # 1.00 less
    ok1, msg1 = verify_zk_inclusion(lower, prover.public_keys)
    try:
        range_prove(ec.N - 500000, 7, currency)                          # "-5,000.00"
        negative_possible = True
    except ValueError:
        negative_possible = False
    real = range_prove(5, 11, currency)                                  # borrow a valid proof...
    swapped = dict(real, C=ec.encode(commit(ec.N - 500000, 11)).hex())   # ...for a negative amount
    return {"caught": (not ok1) and (not negative_possible) and not range_verify(swapped, currency),
            "employer": employer_id, "currency": currency, "lower_msg": msg1, "negative_possible": negative_possible,
            "swap_accepted": range_verify(swapped, currency)}


def quantum_attacker() -> dict:
    h, f = harvest_now_decrypt_later(), forge_audit_seal()
    return {"caught": h["hybrid_read"] is None and not f["fairrun_accepts_forgery"],
            "classical_read": h["classical_read"], "hybrid_error": h["hybrid_error"],
            "classical_forgery": f["classical_accepts_forgery"], "fairrun_forgery": f["fairrun_accepts_forgery"],
            "sizes": {**h["sizes"], **f["sizes"]}}


def payroll_pirate(aw, employers) -> dict:
    """The 2025-26 'payroll pirates' attack: take over ONE login and redirect someone's pay.
    Runs on a fresh world (pass a new mock and employers), never on the story's data."""
    fr = FairRun(aw)
    for e in employers:
        fr.fraud.remember(e)
    bright = next(e for e in employers if e.employer_id == "acct_bright")
    aw.balances["acct_bright"]["GBP"] = to_minor(5000)
    tom = bright.contractors[0]
    cid, acct = tom.contractor_id, bright.employer_id
    steps, n = [], [0]

    def payday(label: str) -> bool:
        n[0] += 1
        res = fr.run_employer(bright, f"pirate-{n[0]}", employers)
        q = res.approvals.get(cid, {})
        paid = cid in res.paid
        steps.append({"step": label, "paid": paid, "valid": list(q.get("valid", [])),
                      "rejected": list(q.get("rejected", [])), "why": q.get("why", "")})
        return paid

    # The pirate changes Tom's bank details through Tom's hijacked login.
    bright.contractors[0] = dataclasses.replace(tom, bank_account="GB-77-11-22-99887766")
    p0 = payday("Pirate changes Tom's bank account")
    req = fr.quorum.requests[(acct, cid)]["req"]

    fr.quorum.approve(acct, cid, "contractor")                       # the stolen login can approve
    p1 = payday("Pirate approves, using Tom's stolen login")

    fr.quorum.submit(acct, cid, fr.quorum.sign_as("contractor", req))
    p2 = payday("Pirate sends the same approval again")

    fake = HybridSigner.generate()                                   # the pirate's own key, not registered
    fr.quorum.submit(acct, cid, fr.quorum.sign_as("employer", req, signer=fake))
    p3 = payday("Pirate forges the employer's approval with their own key")

    other = dict(req, contractor="bright-sara", id="copied")         # a real approval for someone else
    fr.quorum.submit(acct, cid, fr.quorum.sign_as("platform", other))
    p4 = payday("Pirate copies a real approval made for another worker")
    pirate_paid = any([p0, p1, p2, p3, p4])

    # The genuine case: Tom really changed banks. Two independent parties approve, then he is paid.
    bright.contractors[0] = dataclasses.replace(tom, bank_account="GB-30-99-88-12345678")
    payday("Tom genuinely changes banks: new request opened")
    fr.quorum.approve(acct, cid, "platform")                         # call-back to the phone on file
    fr.quorum.approve(acct, cid, "employer")                         # Bright's payroll admin
    genuine = payday("Platform call-back + employer approve the genuine change")
    ok, _ = fr.ledger.verify_chain()
    return {"caught": (not pirate_paid) and genuine, "pirate_paid": pirate_paid, "genuine_paid": genuine,
            "steps": steps, "audit_intact": ok}


def spend_moved_money() -> dict:
    """Move Cedar's money into Alpha's wallet, then run Alpha's payday so the stolen money is spent on wages."""
    from .baseline import run_custom
    r = run_custom({"balances": {"acct_alpha": 6000, "acct_bright": 1200, "acct_cedar": 9000}, "amounts": {},
                    "employer": "acct_alpha", "timeout": False, "replay": False, "pirate": None,
                    "move": ("acct_cedar", "acct_alpha", 2000)})
    f, t = r["fairrun"], r["typical"]
    return {"caught": f["spent_moved"] == 0 and f["move"]["caught"], "fairrun_spent": f["spent_moved"],
            "typical_spent": t["spent_moved"], "detail": f["move"]["detail"],
            "left_in_alpha": f["balances"]["acct_alpha"].get("USD", 0),
            "line": next((x for x in f["lines"] if x.startswith("QUARANTINED")), "")}
