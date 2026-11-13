"""Z3 plan check. Runs before any money moves.

Rules (each tracked by name, so a failure says exactly which rule broke):
  R1 own_funds      every payout leaves from the plan's own employer wallet
  R2 within_balance total cost (payouts + fees + FX + platform fee) <= that wallet's balance
  R3 not_replayed   this batch key has never executed before
  R4 one_per_contractor at most one live payout per contractor in this period

Z3 checks the PLAN against these rules. It does not prove the rest of the code bug-free.
"""
from __future__ import annotations

from dataclasses import dataclass

import z3

from .models import Plan, to_major


RULES = ["R1_own_funds", "R2_within_balance", "R3_not_replayed", "R4_one_per_contractor"]


def _track(solver, rules, name, expr):
    rules[name] = expr
    solver.assert_and_track(expr, name)


def _is_tracker(a) -> bool:
    # assert_and_track adds "label => rule"; skip those when re-checking one rule at a time
    return z3.is_implies(a) and str(a.arg(0)) in RULES


@dataclass
class Verdict:
    ok: bool
    broken_rules: list[str]
    detail: list[str]


def verify(plan: Plan, wallet_balance: int, executed_batches: set[str],
           live_contractors: set[str]) -> Verdict:
    s = z3.Solver()
    s.set(unsat_core=True)

    balance = z3.Int("balance")
    s.add(balance == wallet_balance)

    # R1: model each payout's source as an integer id; employer's own wallet is id 0.
    rules: dict = {}
    own_checks = []
    for i, p in enumerate(plan.payouts):
        src = z3.Int(f"src_{i}")
        s.add(src == (0 if p.source_account == plan.employer_id else 1))
        own_checks.append(src == 0)
    _track(s, rules, "R1_own_funds", z3.And(own_checks) if own_checks else z3.BoolVal(True))

    # R2: total wallet cost must fit inside this employer's balance only.
    cost = z3.Int("cost")
    s.add(cost == plan.wallet_cost)
    _track(s, rules, "R2_within_balance", cost <= balance)

    # R3: batch key not previously executed.
    replayed = z3.Bool("replayed")
    s.add(replayed == (plan.batch_key in executed_batches))
    _track(s, rules, "R3_not_replayed", z3.Not(replayed))

    # R4: no contractor paid twice (within plan, or already live this period).
    ids = [p.contractor_id for p in plan.payouts]
    dup_inside = len(ids) != len(set(ids))
    already = sorted(set(ids) & live_contractors)
    clash = z3.Bool("contractor_clash")
    s.add(clash == (dup_inside or bool(already)))
    _track(s, rules, "R4_one_per_contractor", z3.Not(clash))

    if s.check() == z3.sat:
        return Verdict(True, [], [])

    # Report EVERY broken rule, not just the first conflict Z3 finds:
    # re-check each tracked rule on its own against the same facts.
    broken = []
    for name in RULES:
        single = z3.Solver()
        single.add(*[a for a in s.assertions() if not _is_tracker(a)])
        single.add(rules[name])
        if single.check() == z3.unsat:
            broken.append(name)
    detail = []
    if "R1_own_funds" in broken:
        bad = [p.contractor_id for p in plan.payouts if p.source_account != plan.employer_id]
        detail.append(f"payouts {bad} would use another wallet's funds")
    if "R3_not_replayed" in broken:
        detail.append(f"batch {plan.batch_key} already executed")
    if "R4_one_per_contractor" in broken:
        detail.append(f"contractors already paid or duplicated: {already or ids}")
    if "R2_within_balance" in broken:
        detail.append(f"needs {to_major(plan.wallet_cost)} but wallet holds {to_major(wallet_balance)} "
                      f"(short by {to_major(plan.wallet_cost - wallet_balance)})")
    return Verdict(False, broken, detail)


def smallest_fix(plan: Plan, wallet_balance: int) -> int:
    """The smallest deposit into THIS employer's wallet that makes the plan pass R2 (0 if it already does).
    Solved with Z3's optimiser, so the answer comes from the same rule the check uses."""
    top_up = z3.Int("top_up")
    opt = z3.Optimize()
    opt.add(top_up >= 0, plan.wallet_cost <= wallet_balance + top_up)
    opt.minimize(top_up)
    opt.check()
    return opt.model().eval(top_up, model_completion=True).as_long()


def prove_no_borrowing(payouts: int = 4, employers: int = 3) -> dict:
    """T3, for ALL amounts and balances (symbolic), not for the demo's numbers:
    if a plan passes R1 and R2, then executing it leaves every OTHER employer's balance unchanged and never
    overdraws its own wallet. Drop R1 or R2 and Z3 finds a concrete counterexample."""
    amt = [z3.Int(f"amount_{i}") for i in range(payouts)]
    src = [z3.Int(f"source_{i}") for i in range(payouts)]              # wallet each payout leaves from; 0 = own
    bal = [z3.Int(f"balance_{j}") for j in range(employers)]
    fee = z3.Int("platform_fee")
    world = [a >= 0 for a in amt] + [b >= 0 for b in bal] + [fee >= 0] + [z3.And(x >= 0, x < employers) for x in src]
    cost = z3.Sum(amt) + fee
    after = [bal[j] - z3.Sum([z3.If(src[i] == j, amt[i], 0) for i in range(payouts)]) - (fee if j == 0 else 0)
             for j in range(employers)]
    r1 = z3.And([x == 0 for x in src])
    r2 = cost <= bal[0]
    safe = z3.And(after[0] >= 0, *[after[j] == bal[j] for j in range(1, employers)])

    def counterexample(*rules):
        s = z3.Solver()
        s.add(*world, *rules, z3.Not(safe))
        if s.check() != z3.sat:
            return None
        m = s.model()
        val = lambda x: m.eval(x, model_completion=True).as_long()
        return {"balances": [val(b) for b in bal], "amounts": [val(a) for a in amt],
                "sources": [val(x) for x in src], "after": [val(a) for a in after]}

    return {"T3_checked_plan_never_touches_other_employers": counterexample(r1, r2) is None,
            "without_R1": counterexample(r2), "without_R2": counterexample(r1),
            "payouts": payouts, "employers": employers}
