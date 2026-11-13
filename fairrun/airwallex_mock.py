"""A mock of the Airwallex sandbox behaviours FairRun depends on.

It copies real sandbox quirks noted in the builder guide and Slack:
- every call is scoped to one account (like the x-on-behalf-of header),
- request_id reuse is rejected (duplicate_request_id),
- simulated deposits take no request_id (so retries are NOT safe),
- a transfer can "time out" after Airwallex already accepted it (ambiguous outcome),
- failed transfers end in CANCELLED, not FAILED.
Swap for `airwallex_real.RealAirwallex` once platform access is enabled.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass


class AirwallexError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


class AmbiguousTimeout(Exception):
    """The request may or may not have been processed. Caller must check before retrying."""


# Fixed demo rates: how many units of `buy` one unit of `sell` buys.
RATES = {("USD", "EUR"): 0.92, ("USD", "GBP"): 0.79, ("EUR", "USD"): 1.087, ("GBP", "USD"): 1.266}


@dataclass
class Transfer:
    transfer_id: str
    request_id: str
    account: str
    currency: str
    amount: int
    fee: int
    status: str            # PROCESSING | SENT | PAID | CANCELLED
    failure_type: str | None = None


class MockAirwallex:
    def __init__(self):
        self.balances: dict[str, dict[str, int]] = {}
        self.transfers: dict[str, Transfer] = {}
        self.charges: list[dict] = []
        self.seen_request_ids: set[str] = set()
        self._ids = itertools.count(1)
        self.fail_next_timeout_after_accept = False   # test hook for ambiguous outcomes

    # --- setup helpers ---------------------------------------------------
    def open_account(self, account: str) -> None:
        self.balances.setdefault(account, {})

    def simulate_deposit(self, account: str, currency: str, amount: int) -> None:
        """Like POST /simulation/deposit/create: no request_id, so a blind retry double-credits."""
        bal = self.balances[account]
        bal[currency] = bal.get(currency, 0) + amount

    # --- reads -----------------------------------------------------------
    def get_balances(self, account: str) -> dict[str, int]:
        return dict(self.balances[account])

    def find_transfer_by_request_id(self, account: str, request_id: str) -> Transfer | None:
        for t in self.transfers.values():
            if t.account == account and t.request_id == request_id:
                return t
        return None

    # --- writes ----------------------------------------------------------
    def _claim_request_id(self, request_id: str) -> None:
        if request_id in self.seen_request_ids:
            raise AirwallexError("duplicate_request_id", f"request_id {request_id} already used")
        self.seen_request_ids.add(request_id)

    def _debit(self, account: str, currency: str, amount: int, code: str) -> None:
        bal = self.balances[account]
        if bal.get(currency, 0) < amount:
            raise AirwallexError(code, f"{account} has {bal.get(currency, 0)} {currency}, needs {amount}")
        bal[currency] -= amount

    def convert(self, account: str, request_id: str, sell: str, buy: str, buy_amount: int) -> int:
        self._claim_request_id(request_id)
        rate = RATES[(sell, buy)]
        sell_amount = int(round(buy_amount / rate + 0.4999))  # round up: never under-fund
        self._debit(account, sell, sell_amount, "insufficient_funds")
        bal = self.balances[account]
        bal[buy] = bal.get(buy, 0) + buy_amount
        return sell_amount

    def create_transfer(self, account: str, request_id: str, currency: str, amount: int, fee: int,
                        **_ignored) -> Transfer:
        self._claim_request_id(request_id)
        self._debit(account, currency, amount + fee, "balance_insufficient")
        t = Transfer(f"tfr_{next(self._ids)}", request_id, account, currency, amount, fee, "PROCESSING")
        self.transfers[t.transfer_id] = t
        if self.fail_next_timeout_after_accept:
            self.fail_next_timeout_after_accept = False
            raise AmbiguousTimeout("network timeout after the request was sent")
        return t

    def simulate_transition(self, transfer_id: str, status: str, failure_type: str | None = None,
                            **_ignored) -> Transfer:
        t = self.transfers[transfer_id]
        t.status = status
        if status == "CANCELLED":
            t.failure_type = failure_type
            self.balances[t.account][t.currency] += t.amount + t.fee   # funds returned
        return t

    def create_charge(self, source: str, platform: str, request_id: str, currency: str, amount: int) -> None:
        self._claim_request_id(request_id)
        self._debit(source, currency, amount, "insufficient_fund")
        pb = self.balances.setdefault(platform, {})
        pb[currency] = pb.get(currency, 0) + amount
        self.charges.append({"source": source, "currency": currency, "amount": amount})
