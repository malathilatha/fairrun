import dataclasses

from fairrun.airwallex_mock import MockAirwallex
from fairrun.engine import PLATFORM_ACCOUNT, FairRun
from fairrun.fair_split import fair_split
from fairrun.ledger import Ledger
from fairrun.models import Contractor, Employer, Payout, to_minor
from fairrun.pricing import price_plan
from fairrun.verifier import verify
from scenarios.demo_run import build_world


def test_rejects_other_employers_money():
    _, (alpha, bright, _) = build_world()
    plan = price_plan(bright, "W1")
    stolen = dataclasses.replace(plan.payouts[0], source_account=alpha.employer_id)
    plan.payouts[0] = stolen
    v = verify(plan, to_minor(99999), set(), set())
    assert not v.ok and "R1_own_funds" in v.broken_rules


def test_short_employer_never_uses_other_wallets():
    aw, employers = build_world()
    fr = FairRun(aw)
    others_before = {a: aw.get_balances(a) for a in ("acct_alpha", "acct_cedar")}
    res = fr.run_employer(employers[1], "W1", employers)
    assert res.status == "PAID_PARTIAL"
    assert {a: aw.get_balances(a) for a in ("acct_alpha", "acct_cedar")} == others_before
    assert aw.get_balances("acct_bright")["GBP"] >= 0


def test_fair_split_gives_equal_share():
    _, (_, bright, _) = build_world()
    split, share = fair_split(bright, to_minor(1200))
    ratios = [split[c.contractor_id] / c.amount for c in bright.contractors]
    assert max(ratios) - min(ratios) < 0.01 and 0 < share < 1000


def test_replayed_batch_is_blocked():
    aw, employers = build_world()
    fr = FairRun(aw)
    fr.run_employer(employers[2], "W1", employers)
    aw.simulate_deposit("acct_cedar", "USD", to_minor(50000))
    res = fr.run_employer(employers[2], "W1", employers)
    assert res.status == "BLOCKED"


def test_timeout_does_not_double_pay():
    aw, employers = build_world()
    fr = FairRun(aw)
    aw.fail_next_timeout_after_accept = True
    fr.run_employer(employers[0], "W1", employers)
    paid_to_anna = [t for t in aw.transfers.values() if t.amount == to_minor(2400)]
    assert len(paid_to_anna) == 1


def test_bank_change_is_held():
    aw, employers = build_world()
    fr = FairRun(aw)
    bright = employers[1]
    aw.simulate_deposit("acct_bright", "GBP", to_minor(5000))
    fr.run_employer(bright, "W1", employers)
    bright.contractors[0] = dataclasses.replace(bright.contractors[0], bank_account="GB-99-99-99-00000000")
    res = fr.run_employer(bright, "W2", employers)
    assert "bright-tom" in res.held and "bright-tom" not in res.paid


def test_log_tampering_is_detected():
    led = Ledger()
    led.log("decision", "acct_x", note="pay 100")
    led.log("decision", "acct_x", note="pay 200")
    assert led.verify_chain() == (True, None)
    led.db.execute("UPDATE log SET body='{\"note\": \"pay 999\"}' WHERE seq=1")
    ok, bad_seq = led.verify_chain()
    assert not ok and bad_seq == 1


def test_planner_holds_bank_change_message_offline(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from fairrun.agent import PlannerAgent
    read = PlannerAgent().read_request("Please pay my new bank account today, urgent!", "Tom")
    assert read["kind"] == "bank_change"
    assert read["recommended_action"] == "hold_for_out_of_band_check"
    assert "urgency pressure" in read["red_flags"]


def test_reviewer_rejects_foreign_wallet_offline(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from fairrun.agent import ReviewerAgent
    out = ReviewerAgent().review("Bright", {"employer": "acct_bright", "payouts": [
        {"contractor": "t", "source": "acct_alpha", "currency": "GBP", "amount": 1}]}, [])
    assert out["verdict"] == "REJECT"


def test_reviewer_reject_blocks_payment(monkeypatch):
    aw, employers = build_world()
    fr = FairRun(aw)
    monkeypatch.setattr(fr.reviewer, "review", lambda *a, **k: {"verdict": "REJECT", "reason": "test",
                                                                  "source": "test"})
    before = aw.get_balances("acct_cedar")
    res = fr.run_employer(employers[2], "W1", employers)
    assert res.status == "BLOCKED" and aw.get_balances("acct_cedar") == before


def test_demo_story_runs_end_to_end(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from scenarios.demo_run import main
    main()
    out = capsys.readouterr().out
    assert "hash chain intact: True" in out and "HOLD bright-tom" in out


# --- security layer --------------------------------------------------------
import pytest
from cryptography.exceptions import InvalidTag

from fairrun.audit import AuditSealer, verify_receipt
from fairrun.crypto import EmployerVault, HybridSigner, ShreddedError, verify_signature


def test_each_employer_data_is_sealed_to_its_own_key():
    v = EmployerVault.create()
    rec = v.encrypt("acct_alpha", "DE89370400440532013000")
    v.encrypt("acct_bright", "GB-40-47-84-70872490")
    assert v.decrypt("acct_alpha", rec) == "DE89370400440532013000"
    with pytest.raises(InvalidTag):
        v.decrypt("acct_bright", rec)             # Bright's key cannot open Alpha's record


def test_crypto_shredding_makes_data_unreadable():
    v = EmployerVault.create()
    rec = v.encrypt("acct_alpha", "secret")
    v.shred("acct_alpha")
    with pytest.raises(ShreddedError):
        v.decrypt("acct_alpha", rec)


def test_kem_rotation_keeps_data_readable():
    v = EmployerVault.create("x25519+ml-kem-768/v1")
    rec = v.encrypt("acct_alpha", "secret")
    assert v.rotate_kem("x25519+ml-kem-1024/v2") == 1
    assert v.wrapped["acct_alpha"]["alg"] == "x25519+ml-kem-1024/v2"
    assert v.decrypt("acct_alpha", rec) == "secret"


def test_hybrid_signature_needs_both_parts():
    s = HybridSigner.generate()
    sig = s.sign(b"root")
    assert verify_signature(s.public(), b"root", sig)
    broken = dict(sig, ml_dsa=HybridSigner.generate().sign(b"root")["ml_dsa"])
    assert not verify_signature(s.public(), b"root", broken)   # valid Ed25519 alone is not enough


def _sealed_world():
    aw, employers = build_world()
    fr = FairRun(aw)
    for e in employers:
        fr.run_employer(e, "W1", employers)
    sealer = AuditSealer(fr.ledger)
    return fr, sealer, sealer.seal()


def test_receipt_verifies_and_shows_only_own_entries():
    fr, sealer, seal = _sealed_world()
    r = sealer.receipt(seal, "acct_bright")
    ok, msg = verify_receipt(r, sealer.public_keys)
    assert ok, msg
    assert r["items"] and all(i["employer"] == "acct_bright" for i in r["items"])


def test_tampered_receipt_is_detected():
    fr, sealer, seal = _sealed_world()
    r = sealer.receipt(seal, "acct_bright")
    r["items"][0]["body"]["amount"] = 999999
    assert not verify_receipt(r, sealer.public_keys)[0]


def test_signer_rotation_keeps_old_receipts_valid():
    fr, sealer, seal = _sealed_world()
    old = sealer.receipt(seal, "acct_alpha")
    old_keys = dict(sealer.public_keys)
    sealer.rotate_signer("ed25519+ml-dsa-87/v2")
    assert verify_receipt(old, old_keys)[0]                       # issued before rotation
    new = sealer.receipt(seal, "acct_alpha")
    ok, msg = verify_receipt(new, {"ed25519+ml-dsa-87/v2": sealer.public_keys["ed25519+ml-dsa-87/v2"]})
    assert ok and "ml-dsa-87" in msg


def test_rate_direction_is_never_guessed():
    from fairrun.airwallex_real import RealAirwallex as R
    assert abs(R._buy_per_sell({"currency_pair": "EURUSD", "rate": 1.12496}, "USD", "EUR") - 0.88892) < 1e-4
    assert R._buy_per_sell({"rate_details": [{"buy_amount": "889", "sell_amount": "1000"}]}, "USD", "EUR") == 0.889
    with pytest.raises(ValueError):
        R._buy_per_sell({"rate": 1.12}, "USD", "EUR")


def test_real_fx_cost_is_rechecked_before_paying():
    aw, (alpha, *_rest) = build_world()
    fr = FairRun(aw)
    original = aw.convert
    aw.convert = lambda *a, **k: original(*a, **k) + to_minor(9000)   # provider charges far more than planned
    paid_before = len(aw.transfers)
    res = fr.run_employer(alpha, "W1", [alpha])
    assert res.status == "BLOCKED" and len(aw.transfers) == paid_before


# --- proof of segregated funds ---------------------------------------------
import copy
import json

from fairrun.solvency import FundsBook, SolvencyProver, prove_lemmas, verify_inclusion

ACCTS = ["acct_alpha", "acct_bright", "acct_cedar"]


def _proof_world():
    aw, _ = build_world()
    book = FundsBook.snapshot(aw, ACCTS)
    prover = SolvencyProver()
    return aw, book, prover, prover.prove(book, aw)


def test_z3_lemmas_hold_and_find_the_attacks():
    lem = prove_lemmas()
    assert lem["T1_leaf_le_root"] and lem["T2_segregated_implies_solvent"]
    assert lem["T1_attack_without_check"] and lem["T2_solvent_not_segregated_example"]


def test_every_employer_verifies_its_own_inclusion():
    aw, _, prover, proof = _proof_world()
    assert proof["statement"]["segregated"]
    for a in ACCTS:
        p = prover.inclusion_proof(proof, a)
        assert verify_inclusion(p, prover.public_keys, aw.get_balances(a))[0]
        assert not any(x in str(p["path"]) for x in ACCTS)       # proof names no other employer


def test_commingling_passes_total_check_but_fails_segregation():
    aw, book, prover, _ = _proof_world()
    aw.balances["acct_cedar"]["USD"] -= to_minor(500)
    aw.balances["acct_alpha"]["USD"] += to_minor(500)
    proof = prover.prove(book, aw)
    assert proof["pooled_ok"] and not proof["statement"]["segregated"]
    assert proof["breaches"] == ["acct_cedar:USD"]
    ok, msg = verify_inclusion(prover.inclusion_proof(proof, "acct_cedar"), prover.public_keys,
                               aw.get_balances("acct_cedar"))
    assert not ok and "500.00 USD" in msg


def test_forged_inclusion_proofs_are_rejected():
    aw, _, prover, proof = _proof_world()
    p = prover.inclusion_proof(proof, "acct_bright")
    lower = copy.deepcopy(p)
    lower["owed"]["GBP"] -= 1                                     # platform understates what it owes
    assert not verify_inclusion(lower, prover.public_keys)[0]
    neg = copy.deepcopy(p)
    neg["path"][0]["sums"] = {"USD": -100}                        # negative sibling hides liabilities
    assert "negative" in verify_inclusion(neg, prover.public_keys)[1]
    resigned = copy.deepcopy(p)
    resigned["statement"]["owed_total"] = {}                      # statement edited after signing
    assert not verify_inclusion(resigned, prover.public_keys)[0]


# --- zero-knowledge proof of segregated funds ------------------------------
from fairrun import ec
from fairrun.zk_solvency import ZkSolvencyProver, commit, range_prove, range_verify, verify_zk_inclusion


@pytest.fixture(scope="module")
def zk_world():
    aw, _ = build_world()
    book = FundsBook.snapshot(aw, ACCTS)
    zk = ZkSolvencyProver()
    return aw, book, zk, zk.prove(book, aw)


def test_zk_every_employer_verifies_and_sees_no_other_amounts(zk_world):
    aw, book, zk, proof = zk_world
    for a in ACCTS:
        p = zk.inclusion_proof(proof, a)
        assert verify_zk_inclusion(p, zk.public_keys, aw.get_balances(a))[0]
        text = json.dumps(p["path"])
        assert not any(x in text for x in ACCTS)                           # no names
        assert all(set(step) == {"side", "hash", "C", "range"} for step in p["path"])   # no amounts


def test_zk_range_proof_rejects_negative_and_forgery():
    with pytest.raises(ValueError):
        range_prove(ec.N - 5000, 7, "USD")                                  # "-5000" has no proof
    good = range_prove(5, 11, "USD")
    assert range_verify(good, "USD")
    assert not range_verify(dict(good, C=ec.encode(commit(ec.N - 5, 11)).hex()), "USD")
    assert not range_verify(good, "GBP")                                    # bound to its context


def test_zk_forged_inclusion_rejected(zk_world):
    aw, book, zk, proof = zk_world
    p = zk.inclusion_proof(proof, "acct_bright")
    lower = copy.deepcopy(p)
    lower["owed"]["GBP"] -= 1
    assert not verify_zk_inclusion(lower, zk.public_keys)[0]
    bad_bit = copy.deepcopy(p)
    bad_bit["path"][0]["range"]["USD"]["bits"][0][1] = "1"
    assert "non-negative" in verify_zk_inclusion(bad_bit, zk.public_keys)[1]


def test_zk_detects_commingling():
    aw, _ = build_world()
    book = FundsBook.snapshot(aw, ACCTS)
    aw.balances["acct_cedar"]["USD"] -= to_minor(500)
    aw.balances["acct_alpha"]["USD"] += to_minor(500)
    zk = ZkSolvencyProver()
    proof = zk.prove(book, aw)
    assert proof["pooled_ok"] and proof["breaches"] == ["acct_cedar:USD"]
    ok, msg = verify_zk_inclusion(zk.inclusion_proof(proof, "acct_cedar"), zk.public_keys,
                                  aw.get_balances("acct_cedar"))
    assert not ok and "500.00 USD" in msg


# --- dashboard smoke test ---------------------------------------------------
def test_dashboard_situations_work_in_any_order_and_repeat():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../dashboard/app.py", default_timeout=120)
    at.run()
    assert not at.exception

    def click(label):
        next(b for b in at.sidebar.button if b.label.startswith(label)).click().run()
        assert not at.exception
        return (" ".join(str(m.value) for m in at.markdown),
                " ".join(str(w.value) for w in at.warning))

    for _ in range(2):                                        # Tom held, Sara paid, every time
        text, warn = click("5 ·")
        assert "Paid, with a payout held" in text and "bright-tom" in warn
        assert "changed since last run" in warn
    for _ in range(2):                                        # short employer, even right after situation 5
        text, warn = click("2 ·")
        assert "Paid fairly, rest escalated" in text and "Held for a human check" not in warn
    text, _ = click("1 ·")
    assert "Paid in full" in text
    text, _ = click("4 ·")
    assert "Blocked, nothing paid" in text                    # the replay is stopped


# --- Q-Day simulation --------------------------------------------------------
def test_qday_classical_designs_fall_and_fairrun_hybrid_holds():
    from fairrun.quantum_demo import SECRET, run_all
    r = run_all()
    assert r["hndl"]["classical_read"] == SECRET            # classical-only lock opened with the stolen classical key
    assert r["hndl"]["hybrid_read"] is None                 # hybrid lock stays sealed
    f = r["forgery"]
    assert f["genuine_ok"] and f["classical_accepts_forgery"] and not f["fairrun_accepts_forgery"]
    assert r["migration"]["keys_rewrapped"] == 3 and r["migration"]["data_untouched"]


def test_dashboard_quantum_day_situation():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../dashboard/app.py", default_timeout=120)
    at.run()
    next(b for b in at.sidebar.button if b.label.startswith("7 ·")).click().run()
    assert not at.exception
    text = " ".join(str(m.value) for m in at.markdown)
    assert "opened on Q-Day" in text and "forgery rejected" in text and "still sealed" in text


# --- try to cheat FairRun ----------------------------------------------------
def test_every_attack_is_caught_and_the_real_log_is_untouched():
    from fairrun.attacks import edit_audit_log, foreign_wallet, hide_money, quantum_attacker
    aw, employers = build_world()
    fr = FairRun(aw)
    for e in employers:
        fr.run_employer(e, "W1", employers)
    assert foreign_wallet(aw, employers[1], employers[0])["caught"]
    log = edit_audit_log(fr.ledger)
    assert log["caught"] and log["clever_flag"] == log["naive_flag"] + 1
    assert fr.ledger.verify_chain() == (True, None)            # the attack ran on a copy
    zk = ZkSolvencyProver()
    proof = zk.prove(FundsBook.snapshot(aw, ACCTS), aw)
    assert hide_money(zk, proof)["caught"]
    q = quantum_attacker()
    assert q["caught"] and q["sizes"]["ed25519_signature_bytes"] == 64


def test_dashboard_cheat_tab_scores_four_nil():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../dashboard/app.py", default_timeout=180)
    at.run()
    for k in ("a1", "a2", "a3", "a4", "a5", "a6"):
        at.button(key=k).click().run()
        assert not at.exception
    assert any("FairRun 6 · Attackers 0" in str(m.value) for m in at.markdown)


# --- 2-of-3 approval for bank changes ----------------------------------------
def test_one_stolen_login_never_redirects_pay_but_two_approvals_do():
    from fairrun.attacks import payroll_pirate
    r = payroll_pirate(*build_world())
    assert r["caught"] and not r["pirate_paid"] and r["genuine_paid"] and r["audit_intact"]
    assert [x["valid"] for x in r["steps"][1:5]] == [["contractor"]] * 4      # never more than the stolen vote


def test_approval_rules_bound_to_request_and_account():
    from fairrun.approvals import ApprovalQuorum, only_bank_change
    q = ApprovalQuorum()
    req = q.open("acct_bright", "bright-tom", "GB-1")
    q.approve("acct_bright", "bright-tom", "employer")
    q.approve("acct_bright", "bright-tom", "employer")
    assert not q.status("acct_bright", "bright-tom", "GB-1")["released"]   # one role, one vote
    q.approve("acct_bright", "bright-tom", "platform")
    assert q.status("acct_bright", "bright-tom", "GB-1")["released"]
    assert not q.status("acct_bright", "bright-tom", "GB-2")["released"]   # approvals are for GB-1 only
    assert q.open("acct_bright", "bright-tom", "GB-2")["id"] != req["id"]  # a new account = a new request
    assert not only_bank_change("bank details changed since last run; same bank account is paid by other employer(s)")


def test_held_bank_details_are_not_remembered_as_trusted():
    aw, employers = build_world()
    fr = FairRun(aw)
    for e in employers:
        fr.fraud.remember(e)
    bright = employers[1]
    bright.contractors[0] = dataclasses.replace(bright.contractors[0], bank_account="GB-77-11-22-99887766")
    assert "bright-tom" in fr.run_employer(bright, "W1", employers).held
    assert "bright-tom" in fr.run_employer(bright, "W2", employers).held      # still held next payday


def test_dashboard_shows_incident_and_live_numbers():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../dashboard/app.py", default_timeout=180)
    at.run()
    next(b for b in at.sidebar.button if b.label.startswith("2 ·")).click().run()
    assert not at.exception
    text = " ".join(str(m.value) for m in at.markdown)
    assert "This really happened" in text and "Typical agent" in text and "**FairRun**" in text
    labels = [m.label for m in at.metric]
    assert "Z3 maths check" in labels and "Other employers' wallets touched" in labels
    touched = next(m for m in at.metric if m.label == "Other employers' wallets touched")
    assert str(touched.value) == "0"
    next(b for b in at.sidebar.button if b.label.startswith("6 ·")).click().run()
    assert not at.exception
    text = " ".join(str(m.value) for m in at.markdown)
    assert "Cedar" in text and "short by 500.00 USD" in text and "All fine" in text


# --- baseline, stress test, theorem T3, compliance guards --------------------
def test_stress_test_typical_agent_fails_and_fairrun_does_not():
    from fairrun.baseline import METRICS, stress_test
    r = stress_test(40, seed=11)
    t, f = r["typical"], r["fairrun"]
    assert all(t.get(k, 0) > 0 for k, _ in METRICS)                  # the baseline makes every kind of mistake
    assert all(f.get(k, 0) == 0 for k, _ in METRICS)                 # FairRun makes none
    assert f.get("fr_unreconciled", 0) == 0 and f["correct_payments"] >= t["correct_payments"]
    assert t["secret_moves"] == f["secret_moves"] == r["trouble"]["secret_moves"]
    assert stress_test(40, seed=11)["typical"] == t                  # same seed, same cases


def test_your_own_case_runs_both_agents_on_the_same_numbers():
    from fairrun.baseline import run_custom
    r = run_custom({"balances": {"acct_alpha": 15000, "acct_bright": 700, "acct_cedar": 9000}, "amounts": {},
                    "employer": "acct_bright", "timeout": True, "replay": True, "pirate": "bright-tom",
                    "move": ("acct_cedar", "acct_alpha", 750)})
    t, f = r["typical"], r["fairrun"]
    assert t["stats"]["paydays_using_others_money"] and t["stats"]["paid_to_attacker"] and not t["move"]["caught"]
    assert f["move"]["caught"] and "Cedar Labs is short by 750.00 USD" in f["move"]["detail"]
    assert not any(f["stats"].get(k) for k in ("double_payments", "paydays_using_others_money", "paid_to_attacker"))
    assert f["balances"]["acct_alpha"] == {"USD": 1575000}           # Alpha untouched by Bright's payday


def test_t3_checked_plans_never_touch_other_employers_and_smallest_fix():
    from fairrun.pricing import price_plan
    from fairrun.verifier import prove_no_borrowing, smallest_fix
    t = prove_no_borrowing()
    assert t["T3_checked_plan_never_touches_other_employers"]
    assert t["without_R1"] is not None and t["without_R2"] is not None    # each rule is needed
    _, employers = build_world()
    plan = price_plan(employers[1], "W1")
    assert smallest_fix(plan, to_minor(1200)) == plan.wallet_cost - to_minor(1200)
    assert smallest_fix(plan, plan.wallet_cost) == 0


def test_retention_lock_blocks_shredding_until_the_period_ends():
    import time
    from fairrun.crypto import EmployerVault, RetentionError, ShreddedError
    v = EmployerVault.create()
    rec = v.encrypt("acct_alpha", "DE89370400440532013000")
    v.keep_records_until("acct_alpha", time.time() + 4 * 365 * 86400)
    with pytest.raises(RetentionError):
        v.shred("acct_alpha")
    assert v.decrypt("acct_alpha", rec) == "DE89370400440532013000"       # still readable
    v.shred("acct_alpha", now=time.time() + 5 * 365 * 86400)              # after the period
    with pytest.raises(ShreddedError):
        v.decrypt("acct_alpha", rec)


def test_account_numbers_are_masked_before_text_goes_to_the_model():
    from fairrun.agent import mask_pii
    out = mask_pii("Hi, pay my new account US-000987654321 or IBAN DE89370400440532013000, 900.00 GBP today")
    assert "000987654321" not in out and "DE8937" not in out
    assert "[account ending 4321]" in out and "[account ending 3000]" in out and "900.00 GBP" in out


def test_dashboard_side_by_side_own_case_and_stress_tabs():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("../dashboard/app.py", default_timeout=240)
    at.run()
    next(b for b in at.sidebar.button if b.label.startswith("2 ·")).click().run()
    assert not at.exception
    text = " ".join(str(m.value) for m in at.markdown)
    assert "Typical agent" in text and "Alpha Studio's wallet" in text and "Smallest fix" in text
    next(b for b in at.sidebar.button if b.label.startswith("1 ·")).click().run()
    assert "twice after the timeout" in " ".join(str(m.value) for m in at.markdown)
    next(b for b in at.sidebar.button if b.label.startswith("3 ·")).click().run()
    assert "No mistake here" in " ".join(str(m.value) for m in at.markdown)
    at.button(key="stress_go").click().run()
    assert not at.exception
    text = " ".join(str(m.value) for m in at.markdown)
    assert "✅ 0 mistakes" in text and "T3" in text


def test_unexplained_money_is_quarantined_not_spent():
    from fairrun.attacks import spend_moved_money
    r = spend_moved_money()
    assert r["caught"] and r["fairrun_spent"] == 0 and r["typical_spent"] > 0
    assert r["left_in_alpha"] >= to_minor(2000)                       # Cedar's 2,000 USD is still there
    aw, employers = build_world()                                     # and a recorded deposit is spendable
    from fairrun.solvency import FundsBook
    fr = FairRun(aw)
    fr.book = FundsBook.snapshot(aw, [e.employer_id for e in employers])
    res = fr.run_employer(employers[0], "W1", employers)
    assert res.status == "PAID_FULL" and res.quarantined == 0
    assert fr.book.owed["acct_alpha"] == {k: v for k, v in aw.get_balances("acct_alpha").items() if v}


# --- red-team round 2: each of these was a real hole before it was fixed -------------------------------
def _booked_world():
    from fairrun.solvency import FundsBook
    aw, emps = build_world()
    fr = FairRun(aw)
    fr.book = FundsBook.snapshot(aw, [e.employer_id for e in emps])
    return aw, emps, fr


def test_replay_under_a_respelled_period_is_blocked(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    aw, emps, fr = _booked_world()
    assert fr.run_employer(emps[0], "2026-W45", emps).status == "PAID_FULL"
    n = len(aw.transfers)
    for period in ("2026-w45", " 2026-W45 ", "2026-W45​", "２０２６-W45"):
        assert fr.run_employer(emps[0], period, emps).status == "BLOCKED"
    assert len(aw.transfers) == n


def test_reformatted_account_number_still_matches():
    from fairrun.fraud import blind_index
    base = blind_index("US-000987654321")
    for v in ("US 000987654321", "us000987654321", "US.0009.8765.4321", "US‑000987654321", "ＵＳ-000987654321"):
        assert blind_index(v) == base
    assert blind_index("US-000987654322") != base


def test_recreated_worker_with_new_account_is_held(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    aw, emps, fr = _booked_world()
    alpha = emps[0]
    fr.run_employer(alpha, "W1", emps)
    mike = alpha.contractors[2]
    evil = dataclasses.replace(mike, contractor_id="alpha-mike-2", bank_account="US-ATTACKER-999")
    alpha2 = dataclasses.replace(alpha, contractors=alpha.contractors[:2] + [evil])
    res = fr.run_employer(alpha2, "W2", [alpha2] + emps[1:])
    assert "alpha-mike-2" in res.held and "alpha-mike-2" not in res.paid
    assert "new payee" in res.held["alpha-mike-2"]


def test_two_payees_sharing_one_account_are_held(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    aw, emps, fr = _booked_world()
    alpha = emps[0]
    ghost = dataclasses.replace(alpha.contractors[2], contractor_id="alpha-ghost")
    alpha2 = dataclasses.replace(alpha, contractors=alpha.contractors + [ghost])
    res = fr.run_employer(alpha2, "W1", [alpha2] + emps[1:])
    assert {"alpha-mike", "alpha-ghost"} <= set(res.held) and not ({"alpha-mike", "alpha-ghost"} & set(res.paid))


def test_money_slipped_in_during_a_run_is_quarantined_next_run(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    aw, emps, fr = _booked_world()
    real_charge = aw.create_charge

    def charge_and_sneak(*a, **k):                       # Cedar's money lands in Alpha's wallet mid-run
        aw.balances["acct_cedar"]["USD"] -= 100000
        aw.balances["acct_alpha"]["USD"] += 100000
        return real_charge(*a, **k)
    aw.create_charge = charge_and_sneak
    fr.run_employer(emps[0], "W1", emps)
    aw.create_charge = real_charge
    res = fr.run_employer(emps[0], "W2", emps)
    assert res.quarantined == 100000


def test_malformed_approvals_never_crash_or_release(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    aw, emps, fr = _booked_world()
    bright = emps[1]
    fr.run_employer(bright, "W1", emps)
    sara = bright.contractors[1]
    b2 = dataclasses.replace(bright, contractors=[bright.contractors[0],
                                                  dataclasses.replace(sara, bank_account="GB-EVIL-1")])
    world = [emps[0], b2, emps[2]]
    fr.run_employer(b2, "W2", world)
    junk = [{"role": "employer"}, {"role": "employer", "sig": None}, {"role": ["x"], "sig": {}}, "junk",
            {"role": "platform", "sig": {"alg": "x"}}, None]
    fr.quorum.requests[("acct_bright", "bright-sara")]["sigs"] = junk
    res = fr.run_employer(b2, "W3", world)
    assert "bright-sara" in res.held and "bright-sara" not in res.paid
    assert res.approvals["bright-sara"]["valid"] == []


def test_cutting_off_the_end_of_the_log_is_detected(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    aw, emps, fr = _booked_world()
    fr.run_employer(emps[0], "W1", emps)
    assert fr.ledger.verify_chain() == (True, None)
    fr.ledger.db.execute("DELETE FROM log WHERE seq > (SELECT MAX(seq) - 5 FROM log)")
    assert fr.ledger.verify_chain()[0] is False
    from fairrun.attacks import edit_audit_log
    aw, emps, fr = _booked_world()
    fr.run_employer(emps[0], "W1", emps)
    assert edit_audit_log(fr.ledger)["caught"] is True


def test_two_runs_at_the_same_moment_pay_once(monkeypatch):
    import threading, time
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    aw, emps, fr = _booked_world()
    real_convert = aw.convert

    def slow(*a, **k):
        time.sleep(0.2)
        return real_convert(*a, **k)
    aw.convert = slow
    out = []
    threads = [threading.Thread(target=lambda: out.append(fr.run_employer(emps[0], "W1", emps).status))
               for _ in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(out) == ["BLOCKED", "PAID_FULL"] and len(aw.transfers) == 3


def test_unsupported_currency_blocks_cleanly(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    aw, emps, fr = _booked_world()
    alpha = emps[0]
    odd = dataclasses.replace(alpha, contractors=[dataclasses.replace(alpha.contractors[2], currency="JPY")])
    res = fr.run_employer(odd, "W1", [odd] + emps[1:])
    assert res.status == "BLOCKED" and not aw.transfers
