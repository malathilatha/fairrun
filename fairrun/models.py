"""Core data types. All money is integer minor units (cents/pence) to avoid float errors."""
from __future__ import annotations

from dataclasses import dataclass, field


def to_minor(amount: float | str) -> int:
    """Convert a major-unit amount (Airwallex style, e.g. 100.50) to minor units (10050)."""
    from decimal import Decimal, ROUND_HALF_UP
    return int((Decimal(str(amount)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def to_major(minor: int) -> str:
    sign = "-" if minor < 0 else ""
    minor = abs(minor)
    return f"{sign}{minor // 100:,}.{minor % 100:02d}"


@dataclass(frozen=True)
class Contractor:
    contractor_id: str
    name: str
    currency: str          # currency the contractor is paid in
    amount: int            # amount owed this period, minor units, in `currency`
    method: str            # "LOCAL" or "SWIFT"
    bank_account: str      # synthetic account number (encrypted at rest in later steps)
    country: str


@dataclass
class Employer:
    employer_id: str       # connected account id (acct_...) in sandbox; any id in mock
    name: str
    wallet_currency: str   # currency the employer funds payroll in
    contractors: list[Contractor] = field(default_factory=list)


@dataclass(frozen=True)
class Payout:
    """One planned payout. `source_account` is the wallet the money leaves from."""
    employer_id: str
    source_account: str
    contractor_id: str
    currency: str
    amount: int            # minor units, in payout currency
    fee: int               # minor units, in payout currency (SWIFT fee; 0 for LOCAL)
    method: str


@dataclass
class Plan:
    employer_id: str
    period: str                       # e.g. "2026-W45"
    batch_key: str                    # deterministic idempotency key for the batch
    payouts: list[Payout]
    conversions: dict[str, int]       # payout currency -> minor units needed (amount + fees)
    wallet_cost: int                  # total cost in wallet currency, minor units (incl. platform fee)
    platform_fee: int                 # minor units, wallet currency
    note: str = ""
