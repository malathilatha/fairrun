"""Real Airwallex sandbox client with the same interface as MockAirwallex.

Endpoints and field names follow the Airwallex hackathon builder guide (airwallexdev.com/guide).
Status: login and balances are ready to use now. Calls marked [PLATFORM] need Connected Accounts
+ Platform Payments enabled on your sandbox. Test each against the sandbox before the demo;
use the docs MCP for exact payload fields.

Amounts: FairRun works in minor units (cents); Airwallex takes MAJOR units (100 = $100).
"""
from __future__ import annotations

import os
import time

import requests

from .airwallex_mock import AirwallexError, AmbiguousTimeout
from .models import to_major

BASE = "https://api.sandbox.airwallex.com/api/v1"


def _major(minor: int) -> str:
    return to_major(minor).replace(",", "")


class RealAirwallex:
    def __init__(self, client_id: str | None = None, api_key: str | None = None, timeout: float = 20):
        self.client_id = client_id or os.environ["AWX_CLIENT_ID"]
        self.api_key = api_key or os.environ["AWX_API_KEY"]
        self.timeout = timeout
        self._token = None
        self._token_at = 0.0
        # FairRun stores beneficiary ids per contractor once created: {(account, contractor_id): beneficiary_id}
        self.beneficiaries: dict[tuple[str, str], str] = {}

    # --- auth ------------------------------------------------------------
    def _auth(self) -> dict:
        if not self._token or time.time() - self._token_at > 25 * 60:   # tokens last 30 minutes
            r = requests.post(f"{BASE}/authentication/login", timeout=self.timeout,
                              headers={"x-client-id": self.client_id, "x-api-key": self.api_key})
            r.raise_for_status()
            self._token, self._token_at = r.json()["token"], time.time()
        return {"Authorization": f"Bearer {self._token}"}

    def _call(self, method: str, path: str, account: str | None = None, **kw):
        headers = self._auth()
        if account and account != "platform":
            headers["x-on-behalf-of"] = account          # act for the employer's connected account
        try:
            r = requests.request(method, f"{BASE}{path}", headers=headers, timeout=self.timeout, **kw)
        except (requests.Timeout, requests.ConnectionError) as e:
            raise AmbiguousTimeout(str(e)) from e
        if r.status_code >= 400:
            try:
                body = r.json()
            except ValueError:
                body = {"code": str(r.status_code), "message": r.text[:200]}
            raise AirwallexError(body.get("code", str(r.status_code)), body.get("message", ""))
        return r.json() if r.content else {}

    # --- rates -----------------------------------------------------------
    def refresh_rates(self, pairs, account: str | None = None, margin: float = 0.005) -> dict:
        """Load Airwallex's live indicative rate for each (sell, buy) pair into the shared RATES table
        that pricing and the fair split use. A small margin assumes a slightly WORSE rate, so the Z3
        balance check never under-estimates the real cost."""
        from .airwallex_mock import RATES
        used = {}
        for sell, buy in pairs:
            data = self._call("GET", "/fx/rates/current", account,
                              params={"sell_currency": sell, "buy_currency": buy, "sell_amount": "1000"})
            rate = self._buy_per_sell(data, sell, buy)
            RATES[(sell, buy)] = rate * (1 - margin)
            used[(sell, buy)] = round(rate, 6)
        return used

    @staticmethod
    def _buy_per_sell(data: dict, sell: str, buy: str) -> float:
        """How many units of `buy` one unit of `sell` gets. Never guesses the direction:
        uses the amounts if present, otherwise the currency_pair (BASEQUOTE: 1 BASE = rate QUOTE)."""
        if data.get("buy_amount") and data.get("sell_amount"):
            return float(data["buy_amount"]) / float(data["sell_amount"])
        for d in data.get("rate_details") or []:
            if d.get("buy_amount") and d.get("sell_amount"):
                return float(d["buy_amount"]) / float(d["sell_amount"])
        pair = str(data.get("currency_pair", "")).upper().replace("/", "")
        rate = float(data.get("client_rate") or data["rate"])
        if pair == sell + buy:          # e.g. USDEUR 0.89 -> 1 USD = 0.89 EUR
            return rate
        if pair == buy + sell:          # e.g. EURUSD 1.12 -> 1 EUR = 1.12 USD -> 1 USD = 1/1.12 EUR
            return 1 / rate
        raise ValueError("cannot tell the rate direction safely; send this reply to fix the parser: "
                         + str(data)[:400])

    # --- reads -----------------------------------------------------------
    def get_balances(self, account: str) -> dict[str, int]:
        from .models import to_minor
        rows = self._call("GET", "/balances/current", account)
        return {b["currency"]: to_minor(b["available_amount"]) for b in rows}

    def find_transfer_by_request_id(self, account: str, request_id: str):
        """List recent transfers and match request_id (no server-side filter is documented)."""
        data = self._call("GET", "/transfers", account, params={"page_size": 100})
        items = data.get("items", data if isinstance(data, list) else [])
        for t in items:
            if t.get("request_id") == request_id:
                return _T(t["id"], t.get("status", "UNKNOWN"))
        return None

    # --- writes ----------------------------------------------------------
    def convert(self, account, request_id, sell, buy, buy_amount) -> int:
        from .models import to_minor
        body = {"request_id": request_id, "buy_currency": buy, "sell_currency": sell,
                "buy_amount": _major(buy_amount)}
        data = self._call("POST", "/fx/conversions/create", account, json=body)  # no x-api-version on FX
        return to_minor(data.get("sell_amount") or data.get("client_sell_amount") or 0)

    def create_transfer(self, account, request_id, currency, amount, fee, *, contractor_id=None,
                        method="LOCAL", reference="FairRun payroll"):
        beneficiary_id = self.beneficiaries.get((account, contractor_id))
        if not beneficiary_id:
            raise AirwallexError("no_beneficiary", f"create a beneficiary for {contractor_id} first")
        body = {"request_id": request_id, "beneficiary_id": beneficiary_id,
                "transfer_amount": _major(amount), "transfer_currency": currency,
                "source_currency": currency, "transfer_method": method,
                "reference": reference, "reason": "wages_salary"}
        t = self._call("POST", "/transfers/create", account, json=body)
        return _T(t["id"], t.get("status", "PROCESSING"))

    def simulate_transition(self, transfer_id, status, failure_type=None, account=None):
        """Sandbox only: transfers on behalf of a connected account stay PROCESSING until advanced.
        Simulate SENT before PAID or FAILED (guide)."""
        body = {"next_status": status}
        if failure_type:
            body["failure_type"] = failure_type
        return self._call("POST", f"/simulation/transfers/{transfer_id}/transition", account, json=body)

    def create_charge(self, source, platform, request_id, currency, amount):   # [PLATFORM]
        body = {"request_id": request_id, "amount": float(_major(amount)), "currency": currency,
                "source": source, "reason": "professional_business_services",
                "reference": "FairRun platform fee"}
        return self._call("POST", "/charges/create", json=body)

    def load_beneficiaries(self, state: dict) -> None:
        """Map (connected account, contractor_id) -> beneficiary id from employers_sandbox.json."""
        for rec in state.values():
            for cid, bid in rec.get("beneficiaries", {}).items():
                self.beneficiaries[(rec["id"], cid)] = bid

    def simulate_deposit(self, account, global_account_id, amount):
        """No request_id on this endpoint: a blind retry double-credits. Re-read balances first."""
        return self._call("POST", "/simulation/deposit/create", account,
                          json={"global_account_id": global_account_id, "amount": float(_major(amount))})


class _T:
    def __init__(self, transfer_id, status):
        self.transfer_id, self.status = transfer_id, status
