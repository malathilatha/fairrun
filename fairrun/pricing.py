"""Price an employer's payroll: fees first, then the FX each payout currency needs.

Builder-guide rule: calculate SWIFT fees BEFORE converting, or the last payout fails.
"""
from __future__ import annotations

import hashlib

from .airwallex_mock import RATES
from .models import Employer, Payout, Plan

SWIFT_FEE = {"EUR": 1285, "GBP": 1100, "USD": 1500}   # demo values; guide quotes EUR 12.85 per SWIFT payout
PLATFORM_FEE = {"USD": 2500, "GBP": 2000, "EUR": 2300}  # FairRun's own fee per run, wallet currency


def batch_key(employer_id: str, period: str, contractor_ids: list[str]) -> str:
    """Deterministic batch fingerprint: same batch -> same key, so a replay is recognisable."""
    raw = "|".join([employer_id, period, *sorted(contractor_ids)])
    return "batch_" + hashlib.sha256(raw.encode()).hexdigest()[:24]


def wallet_cost_of(currency_needs: dict[str, int], wallet_currency: str) -> int:
    total = 0
    for cur, need in currency_needs.items():
        if cur == wallet_currency:
            total += need
        else:
            total += int(round(need / RATES[(wallet_currency, cur)] + 0.4999))
    return total


def price_plan(employer: Employer, period: str, amounts: dict[str, int] | None = None, note: str = "") -> Plan:
    """Build a plan. `amounts` overrides what each contractor is paid (used for partial runs)."""
    payouts: list[Payout] = []
    needs: dict[str, int] = {}
    for c in employer.contractors:
        amt = c.amount if amounts is None else amounts.get(c.contractor_id, 0)
        if amt <= 0:
            continue
        fee = SWIFT_FEE[c.currency] if c.method == "SWIFT" else 0
        payouts.append(Payout(employer.employer_id, employer.employer_id, c.contractor_id,
                              c.currency, amt, fee, c.method))
        needs[c.currency] = needs.get(c.currency, 0) + amt + fee
    platform_fee = PLATFORM_FEE[employer.wallet_currency]
    cost = wallet_cost_of(needs, employer.wallet_currency) + platform_fee
    key = batch_key(employer.employer_id, period, [p.contractor_id for p in payouts])
    return Plan(employer.employer_id, period, key, payouts, needs, cost, platform_fee, note)
