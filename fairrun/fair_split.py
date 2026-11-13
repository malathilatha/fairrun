"""Fair partial payroll when an employer is short (OR-Tools CP-SAT).

Goal, in order:
 1. maximise the smallest share any contractor receives (everyone gets the same %, as high as possible)
 2. then use any leftover to pay more in total
Only that employer's own budget is available. Fees are counted for every contractor who is paid.
"""
from __future__ import annotations

from ortools.sat.python import cp_model

from .models import Employer
from .pricing import PLATFORM_FEE, SWIFT_FEE, wallet_cost_of


def _cost_in_wallet(employer: Employer, cur: str, amount: int) -> int:
    return wallet_cost_of({cur: amount}, employer.wallet_currency)


def fair_split(employer: Employer, wallet_balance: int) -> tuple[dict[str, int], int]:
    """Return (amount per contractor in their own currency, share achieved in per-mille)."""
    budget = wallet_balance - PLATFORM_FEE[employer.wallet_currency]
    cs = employer.contractors
    if budget <= 0 or not cs:
        return {c.contractor_id: 0 for c in cs}, 0

    # Work in wallet-currency minor units so one budget constraint covers mixed currencies.
    owed_w = [_cost_in_wallet(employer, c.currency, c.amount) for c in cs]
    fee_w = [_cost_in_wallet(employer, c.currency, SWIFT_FEE[c.currency]) if c.method == "SWIFT" else 0
             for c in cs]

    def solve(min_share: int | None):
        m = cp_model.CpModel()
        pay = [m.NewIntVar(0, owed_w[i], f"pay_{i}") for i in range(len(cs))]
        paid = [m.NewBoolVar(f"paid_{i}") for i in range(len(cs))]
        share = m.NewIntVar(0, 1000, "share")
        for i in range(len(cs)):
            m.Add(pay[i] == 0).OnlyEnforceIf(paid[i].Not())
            m.Add(pay[i] >= 1).OnlyEnforceIf(paid[i])
            m.Add(pay[i] * 1000 >= share * owed_w[i])           # everyone gets at least `share`
        m.Add(sum(pay) + sum(fee_w[i] * paid[i] for i in range(len(cs))) <= budget)
        if min_share is None:
            m.Maximize(share)
        else:
            m.Add(share >= min_share)
            m.Maximize(sum(pay))
        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = 5
        status = solver.Solve(m)
        if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            return None, 0
        return [solver.Value(p) for p in pay], solver.Value(share)

    _, best_share = solve(None)
    pays_w, share = solve(best_share)
    if pays_w is None:
        return {c.contractor_id: 0 for c in cs}, 0

    # Convert each wallet-currency amount back to the contractor's currency, rounding DOWN
    # so the plan can never cost more than the budget the solver respected.
    out = {}
    for c, w in zip(cs, pays_w):
        if c.currency == employer.wallet_currency:
            out[c.contractor_id] = w
        else:
            from .airwallex_mock import RATES
            out[c.contractor_id] = int(w * RATES[(employer.wallet_currency, c.currency)])
    return out, share
