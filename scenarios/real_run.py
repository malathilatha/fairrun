"""The FairRun story on the REAL Airwallex sandbox (three ACTIVE connected accounts).

Before running:  onboard_employers.py, prepare_sandbox.py wallets + fund, beneficiaries.py create
Run:             python -m scenarios.real_run [period]

The local ledger (fairrun_sandbox.db) remembers executed batches across runs, so running the same
period twice is BLOCKED on purpose. Use a new period (e.g. 2026-W45-b) and re-run
`prepare_sandbox.py fund` to replay the story.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sys

from fairrun.airwallex_real import RealAirwallex
from fairrun.engine import FairRun
from fairrun.ledger import Ledger
from fairrun.models import Contractor, Employer, to_major, to_minor
from fairrun.solvency import FundsBook
from fairrun.zk_solvency import ZkSolvencyProver, verify_zk_inclusion

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "employers_sandbox.json")
DB = os.path.join(ROOT, "fairrun_sandbox.db")


def build_employers(state: dict) -> list[Employer]:
    a, b, c = state["alpha"]["id"], state["bright"]["id"], state["cedar"]["id"]
    return [
        Employer(a, "Alpha Studio", "USD", [
            Contractor("alpha-anna", "Anna (Berlin)", "EUR", to_minor(2400), "SWIFT", "DE89370400440532013000", "DE"),
            Contractor("alpha-jonas", "Jonas (Munich)", "EUR", to_minor(1800), "SWIFT", "DE02120300000000202051", "DE"),
            Contractor("alpha-mike", "Mike (Austin)", "USD", to_minor(3000), "LOCAL", "026009593-000123456789", "US"),
        ]),
        Employer(b, "Bright Bakery", "GBP", [
            Contractor("bright-tom", "Tom (Leeds)", "GBP", to_minor(900), "LOCAL", "404784-70872490", "GB"),
            Contractor("bright-sara", "Sara (York)", "GBP", to_minor(600), "LOCAL", "200000-55779911", "GB"),
        ]),
        Employer(c, "Cedar Labs", "USD", [
            Contractor("cedar-lee", "Lee (Denver)", "USD", to_minor(4200), "LOCAL", "026009593-000987654321", "US"),
            Contractor("cedar-ria", "Ria (Seattle)", "USD", to_minor(3900), "LOCAL", "026009593-000555000111", "US"),
        ]),
    ]


def show(title, res):
    print(f"\n=== {title} -> {res.status} ===")
    for line in res.explanation:
        print("  -", line)


def run(fr, employer, period, employers, **kw):
    try:
        return fr.run_employer(employer, period, employers, **kw)
    except Exception as e:   # surface real API problems clearly instead of a long traceback
        print(f"\n!!! {employer.name}: {type(e).__name__}: {e}")
        return None


def main():
    period = sys.argv[1] if len(sys.argv) > 1 else "2026-W45-live"
    state = json.load(open(STATE))
    aw = RealAirwallex()
    aw.load_beneficiaries(state)
    employers = build_employers(state)
    alpha, bright, cedar = employers

    live = aw.refresh_rates([("USD", "EUR")], account=alpha.employer_id)
    print(f"Live Airwallex rate USD->EUR: {live[('USD', 'EUR')]} (pricing assumes 0.5% worse, to stay safe)")
    print(f"Period: {period}. Every check uses ONE employer's own wallet, read live from Airwallex.\n")

    fr = FairRun(aw, Ledger(DB))

    r = run(fr, alpha, period, employers)
    if r: show("Alpha Studio: normal run with FX", r)

    r = run(fr, bright, period, employers)
    if r: show("Bright Bakery: shortfall", r)

    print("\n=== Cedar's late deposit lands mid-run (real simulated deposit) ===")
    before = aw.get_balances(bright.employer_id).get("GBP", 0)
    aw.simulate_deposit(cedar.employer_id, state["cedar"]["global_account_id"], to_minor(9000))
    import time
    time.sleep(3)                          # sandbox posts deposits within a few seconds
    after = aw.get_balances(bright.employer_id).get("GBP", 0)
    print(f"  - Cedar wallet now {to_major(aw.get_balances(cedar.employer_id).get('USD', 0))} USD")
    print(f"  - Bright wallet before {to_major(before)} GBP / after {to_major(after)} GBP: unchanged")

    r = run(fr, cedar, period, employers)
    if r: show("Cedar Labs: run after deposit", r)

    r = run(fr, alpha, period, employers)
    if r: show("Alpha Studio: same batch replayed", r)

    tom = bright.contractors[0]
    bright.contractors[0] = dataclasses.replace(tom, bank_account="026009593-000987654321")
    aw.simulate_deposit(bright.employer_id, state["bright"]["global_account_id"], to_minor(2000))
    email = ("Hi, it's Tom. I changed my bank this week, please send today's pay to my new "
             "account. Urgent, rent is due today!")
    r = run(fr, bright, period + "-next", employers, messages={"bright-tom": email})
    if r:
        show("Bright Bakery next week: bank-detail change", r)
        print("  Summary:", fr.planner.explain(bright.name, r.explanation))

    ok, _ = fr.ledger.verify_chain()
    print(f"\nAudit log ({os.path.basename(DB)}): {len(fr.ledger.entries())} entries, hash chain intact: {ok}")

    # Proof of Segregated Funds against LIVE Airwallex balances (read-only, moves no money)
    accts = [e.employer_id for e in employers]
    book = FundsBook.snapshot(aw, accts)
    prover = ZkSolvencyProver()
    proof = prover.prove(book, aw)
    st = proof["statement"]
    print(f"\nZero-knowledge Proof of Segregated Funds: root {st['root'][:16]}..., segregated: {st['segregated']}")
    for e in employers:
        p = prover.inclusion_proof(proof, e.employer_id)
        ok, msg = verify_zk_inclusion(p, prover.public_keys, aw.get_balances(e.employer_id))
        print(f"  - {e.name:14} own-account check: {ok} ({msg})")


if __name__ == "__main__":
    main()
