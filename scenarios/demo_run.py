"""The FairRun demo story, end to end, on the mock Airwallex.

Run:  python -m scenarios.demo_run
"""
from __future__ import annotations

import dataclasses

from cryptography.exceptions import InvalidTag

from fairrun.airwallex_mock import MockAirwallex
from fairrun.audit import AuditSealer, verify_receipt
from fairrun.crypto import EmployerVault, ShreddedError, unb64
from fairrun.fraud import blind_index
from fairrun.engine import PLATFORM_ACCOUNT, FairRun
from fairrun.models import Contractor, Employer, to_major, to_minor
from fairrun.solvency import FundsBook, SolvencyProver, prove_lemmas
from fairrun.zk_solvency import ZkSolvencyProver, verify_zk_inclusion


def build_world():
    aw = MockAirwallex()
    alpha = Employer("acct_alpha", "Alpha Studio", "USD", [
        Contractor("alpha-anna", "Anna (Berlin)", "EUR", to_minor(2400), "SWIFT", "DE89370400440532013000", "DE"),
        Contractor("alpha-jonas", "Jonas (Munich)", "EUR", to_minor(1800), "SWIFT", "DE02120300000000202051", "DE"),
        Contractor("alpha-mike", "Mike (Austin)", "USD", to_minor(3000), "LOCAL", "US-000123456789", "US"),
    ])
    bright = Employer("acct_bright", "Bright Bakery", "GBP", [
        Contractor("bright-tom", "Tom (Leeds)", "GBP", to_minor(900), "LOCAL", "GB-40-47-84-70872490", "GB"),
        Contractor("bright-sara", "Sara (York)", "GBP", to_minor(600), "LOCAL", "GB-20-00-00-55779911", "GB"),
    ])
    cedar = Employer("acct_cedar", "Cedar Labs", "USD", [
        Contractor("cedar-lee", "Lee (Denver)", "USD", to_minor(4200), "LOCAL", "US-000987654321", "US"),
        Contractor("cedar-ria", "Ria (Seattle)", "USD", to_minor(3900), "LOCAL", "US-000555000111", "US"),
    ])
    for acct in ("acct_alpha", "acct_bright", "acct_cedar", PLATFORM_ACCOUNT):
        aw.open_account(acct)
    aw.simulate_deposit("acct_alpha", "USD", to_minor(15000))
    aw.simulate_deposit("acct_bright", "GBP", to_minor(1200))     # short: payroll is 1,500 + fee
    aw.simulate_deposit("acct_cedar", "USD", to_minor(2000))      # Cedar's main deposit is late
    return aw, [alpha, bright, cedar]


def show(title, res):
    print(f"\n=== {title} -> {res.status} ===")
    for line in res.explanation:
        print("  -", line)


def main():
    aw, employers = build_world()
    alpha, bright, cedar = employers
    fr = FairRun(aw)
    period = "2026-W45"

    total = sum(sum(v for v in b.values()) for b in aw.balances.values() if b is not aw.balances[PLATFORM_ACCOUNT])
    print("Naive agent view: 'all wallets together hold", to_major(total), "(mixed currencies) - plenty!'")
    print("FairRun view: each employer is checked against ITS OWN wallet only.")

    # 1. Normal run with FX + SWIFT fees. One payout times out after Airwallex accepted it.
    aw.fail_next_timeout_after_accept = True
    show("Alpha Studio: normal run with FX", fr.run_employer(alpha, period, employers))

    # 2. Bright Bakery is short -> fair partial split + escalation.
    show("Bright Bakery: shortfall", fr.run_employer(bright, period, employers))

    # 3. Cedar's late deposit lands mid-run. Bright's position must not change.
    bright_before = aw.get_balances("acct_bright")
    aw.simulate_deposit("acct_cedar", "USD", to_minor(9000))
    bright_after = aw.get_balances("acct_bright")
    print("\n=== Cedar deposit lands mid-run ===")
    print(f"  - Cedar wallet now {to_major(aw.get_balances('acct_cedar')['USD'])} USD")
    gbp = lambda b: to_major(b.get("GBP", 0))
    print(f"  - Bright wallet before {gbp(bright_before)} GBP / after {gbp(bright_after)} GBP: "
          "unchanged -> Cedar's money stays with Cedar; Bright's shortfall is still escalated")
    show("Cedar Labs: run after deposit", fr.run_employer(cedar, period, employers))

    # 4. Replay: the same Alpha batch is triggered again.
    show("Alpha Studio: duplicate batch replayed", fr.run_employer(alpha, period, employers))

    # 5. Next week: Tom's bank details 'changed' to an account Cedar already pays.
    tom = bright.contractors[0]
    bright.contractors[0] = dataclasses.replace(tom, bank_account="US-000987654321")
    aw.simulate_deposit("acct_bright", "GBP", to_minor(2000))
    email = ("Hi, it's Tom. I changed my bank this week, please send today's pay to my new "
             "account US-000987654321. Urgent, rent is due today!")
    res = fr.run_employer(bright, "2026-W46", employers, messages={"bright-tom": email})
    show("Bright Bakery next week: bank-detail change", res)
    print("  Summary:", fr.planner.explain(bright.name, res.explanation))

    ok, bad = fr.ledger.verify_chain()
    print(f"\nAudit log: {len(fr.ledger.entries())} entries, hash chain intact: {ok}")
    print("Platform fees collected:", {k: to_major(v) for k, v in aw.get_balances(PLATFORM_ACCOUNT).items()})

    security_section(fr, employers)
    solvency_section(aw, employers)


def security_section(fr, employers):
    print("\n" + "=" * 70)
    print("SECURITY: separate keys per employer, sealed audit log, post-quantum ready")
    print("=" * 70)

    # 1. Per-employer encryption of contractor bank details
    vault = EmployerVault.create("x25519+ml-kem-768/v1")
    stored = {e.employer_id: {c.contractor_id: vault.encrypt(e.employer_id, c.bank_account)
                              for c in e.contractors} for e in employers}
    alpha_rec = stored["acct_alpha"]["alpha-anna"]
    print(f"\n[1] Bank details encrypted per employer ({alpha_rec['alg']}, key wrapped with "
          f"{vault.wrapped['acct_alpha']['alg']}).")
    print(f"    Anna's account as stored: {alpha_rec['ct'][:32]}...")
    try:
        vault.decrypt("acct_bright", alpha_rec)
        print("    !! Bright's key opened Alpha's data")
    except InvalidTag:
        print("    Bright's key cannot open Alpha's records: decryption refused.")
    print(f"    Fraud matching still works on blind indexes, e.g. Anna -> "
          f"{blind_index(employers[0].contractors[0].bank_account)[:16]}... (no account number needed)")

    # 2. Seal the audit log once, with a hybrid post-quantum signature
    sealer = AuditSealer(fr.ledger)
    seal = sealer.seal()
    sig = seal["signatures"][0]
    print(f"\n[2] Sealed {seal['entries']} log entries under one Merkle root {seal['root'][:16]}...")
    print(f"    Signed once with {sig['alg']} (Ed25519 {len(unb64(sig['ed25519']))} B + "
          f"ML-DSA {len(unb64(sig['ml_dsa']))} B). Both must verify.")

    # 3. Private receipt for one employer
    receipt = sealer.receipt(seal, "acct_bright")
    ok, msg = verify_receipt(receipt, sealer.public_keys)
    print(f"\n[3] Bright Bakery's receipt: {len(receipt['items'])} of {seal['entries']} entries "
          f"(only its own). Verify: {ok} ({msg})")
    import copy
    forged = copy.deepcopy(receipt)
    forged["items"][0]["body"]["note"] = "edited after the fact"
    print(f"    Same receipt with one entry edited -> verify: {verify_receipt(forged, sealer.public_keys)[0]}")

    # 4. Crypto-agility: rotate algorithms without a rewrite
    old_keys = dict(sealer.public_keys)
    n = vault.rotate_kem("x25519+ml-kem-1024/v2")
    sealer.rotate_signer("ed25519+ml-dsa-87/v2")
    print(f"\n[4] Rotation: {n} employer keys re-wrapped with x25519+ml-kem-1024/v2; "
          f"seals re-signed with ed25519+ml-dsa-87/v2.")
    print(f"    Anna's record still decrypts: {vault.decrypt('acct_alpha', alpha_rec) == employers[0].contractors[0].bank_account}; "
          f"old receipt still verifies with old key: {verify_receipt(receipt, old_keys)[0]}")

    # 5. Crypto-shredding when an employer leaves the platform
    vault.shred("acct_cedar")
    try:
        vault.decrypt("acct_cedar", stored["acct_cedar"]["cedar-lee"])
    except ShreddedError:
        print("\n[5] Cedar Labs offboarded: its key destroyed, all its stored bank data is now unreadable. "
              "Other employers unaffected.")


def solvency_section(aw, employers):
    print("\n" + "=" * 70)
    print("PROOF OF SEGREGATED FUNDS: each employer's money is in its own account")
    print("=" * 70)
    accts = [e.employer_id for e in employers]
    names = {e.employer_id: e.name for e in employers}

    lem = prove_lemmas()
    print(f"\n[6] Z3 theorems (proved for ALL balances in an 8-leaf tree, not tested on examples):")
    print(f"    T1 every included balance <= signed total, with non-negative sums: {lem['T1_leaf_le_root']}")
    a = lem["T1_attack_without_check"]
    print(f"       without the check, Z3 finds the attack: leaves {a['leaves'][:2]} (+ zeros) -> "
          f"signed total {a['root']}: a real 5,000 liability hidden by a fake negative leaf")
    print(f"    T2 per-employer segregation implies total solvency: {lem['T2_segregated_implies_solvent']}")
    g = lem["T2_solvent_not_segregated_example"]
    print(f"       but not the reverse: held {g['held']} vs owed {g['owed']} passes a total-only check "
          "while an employer is short")

    book = FundsBook.snapshot(aw, accts)            # FairRun's books after its reconciled runs

    # The plain Merkle sum tree leaks: Alpha's proof shows its siblings' sums.
    plain = SolvencyProver()
    path = plain.inclusion_proof(plain.prove(book, aw), "acct_alpha")["path"]
    leak = next((step["sums"] for step in path if step["sums"]), {})
    print(f"\n[7] Plain Merkle sum proof: Alpha sees a sibling sum {_money(leak)} -> it can guess another "
          "employer's balance.")

    zk = ZkSolvencyProver()
    proof = zk.prove(book, aw)
    st = proof["statement"]
    print(f"    Zero-knowledge version (Pedersen commitments + range proofs, {st['scheme']}):")
    print(f"    signed root {st['root'][:16]}..., totals {_money(st['owed_total'])}, built in {proof['seconds']} s")
    for e in accts:
        ip = zk.inclusion_proof(proof, e)
        ok, msg = verify_zk_inclusion(ip, zk.public_keys, aw.get_balances(e))
        print(f"    {names[e]:14} verifies offline: {ok} ({msg})")
    sib = zk.inclusion_proof(proof, "acct_alpha")["path"][0]["C"]
    print(f"    What Alpha now sees of its sibling: {next(iter(sib.values()))[:20]}... (a commitment, no amount)")

    # The commingling failure: an operator quietly covers Alpha with Cedar's money.
    moved = min(aw.balances["acct_cedar"].get("USD", 0), 50000)
    aw.balances["acct_cedar"]["USD"] -= moved
    aw.balances["acct_alpha"]["USD"] = aw.balances["acct_alpha"].get("USD", 0) + moved
    proof = zk.prove(book, aw)
    print(f"\n[8] Operator moves {to_major(moved)} USD from Cedar's account to Alpha's, outside FairRun.")
    print(f"    Total-only proof of reserves (what exchanges publish): passes = {proof['pooled_ok']}")
    print(f"    FairRun per-employer check (Z3 R5_segregated): passes = {proof['statement']['segregated']}, "
          f"breach: {proof['breaches']}")
    ok, msg = verify_zk_inclusion(zk.inclusion_proof(proof, "acct_cedar"), zk.public_keys,
                                  aw.get_balances("acct_cedar"))
    print(f"    Cedar Labs checks its own proof: {ok} ({msg})")


def _money(sums: dict) -> str:
    return ", ".join(f"{to_major(v)} {c}" for c, v in sorted(sums.items()) if v) or "0"


if __name__ == "__main__":
    main()
