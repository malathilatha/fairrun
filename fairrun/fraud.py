"""Fraud checks before payout.

1. Bank-detail change since the last run -> hold for human approval (payroll diversion).
2. Same bank account paid by more than one employer -> flag (ghost / diverted account).

Check 2 uses a BLIND INDEX: a keyed HMAC fingerprint of the account number. The platform can
match equal accounts across employers without reading anyone's account number, so it keeps
working after per-employer encryption is added.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import unicodedata

from .models import Employer

_INDEX_KEY = os.environ.get("FAIRRUN_BLIND_INDEX_KEY", "dev-only-blind-index-key").encode()


def blind_index(account_number: str) -> str:
    # Letters and digits only, after Unicode folding: "US-0001", "us 0001", "US.0001" and look-alike
    # characters all give the same fingerprint, so re-formatting an account cannot dodge a match.
    folded = unicodedata.normalize("NFKC", str(account_number)).upper()
    normalised = "".join(ch for ch in folded if ch.isalnum())
    return hmac.new(_INDEX_KEY, normalised.encode(), hashlib.sha256).hexdigest()[:32]


class FraudChecks:
    def __init__(self):
        self.known_accounts: dict[tuple[str, str], str] = {}   # (employer, contractor) -> blind index

    def remember(self, employer: Employer, skip: set[str] | frozenset = frozenset()) -> None:
        """Remember bank details as trusted. Held payees are skipped: unapproved details never become 'known'."""
        for c in employer.contractors:
            if c.contractor_id in skip:
                continue
            self.known_accounts[(employer.employer_id, c.contractor_id)] = blind_index(c.bank_account)

    def check(self, employer: Employer, all_employers: list[Employer]) -> dict[str, str]:
        """Return {contractor_id: reason} for payouts that must be held."""
        holds: dict[str, str] = {}
        owners: dict[str, set[str]] = {}
        for e in all_employers:
            for c in e.contractors:
                owners.setdefault(blind_index(c.bank_account), set()).add(e.employer_id)

        has_history = any(e == employer.employer_id for e, _ in self.known_accounts)
        mine: dict[str, list[str]] = {}
        for c in employer.contractors:
            mine.setdefault(blind_index(c.bank_account), []).append(c.contractor_id)

        for c in employer.contractors:
            idx = blind_index(c.bank_account)
            before = self.known_accounts.get((employer.employer_id, c.contractor_id))
            reasons = []
            if before is not None and before != idx:
                reasons.append("bank details changed since last run (confirm out-of-band)")
            if before is None and has_history:
                # Deleting a worker and re-adding them under a new id must not dodge the bank-change hold.
                reasons.append("new payee since last run (first payment needs approval)")
            other_employers = sorted(owners.get(idx, set()) - {employer.employer_id})
            if other_employers:
                reasons.append(f"same bank account is paid by other employer(s) {other_employers}")
            twins = sorted(set(mine[idx]) - {c.contractor_id})
            if twins:
                reasons.append(f"same bank account is used by another payee of this employer {twins}")
            if reasons:
                holds[c.contractor_id] = "; ".join(reasons)
        return holds
