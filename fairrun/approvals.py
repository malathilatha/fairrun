"""2-of-3 approval for bank-detail changes: one stolen login is never enough to redirect pay.

The real attack ("payroll pirates", 2025-26): attackers take over ONE account (an employee's HR login,
often via a help-desk password/MFA reset) and change the bank details. Pay goes to the attacker, and
nobody notices until payday.

FairRun's rule: a payout to NEW bank details is released only when k = 2 of n = 3 independent parties
have signed an approval of exactly that change:

    employer    the employer's payroll admin
    platform    the platform's call-back to the contractor's phone already on file (not the one in the request)
    contractor  the contractor, from their own login

How it works (a k-of-n multi-signature quorum):
1. When a bank change is detected, FairRun opens an approval request:
       {request id, employer, contractor, blind index of the NEW account}
   The account number itself is never in the request: only its keyed HMAC fingerprint (blind index).
2. Each party signs that exact request with its own hybrid key (Ed25519 + ML-DSA-65; both must verify).
3. FairRun counts DISTINCT roles with a valid signature from that role's registered public key.
   - The same approval sent twice counts once (one role, one vote).
   - A signature from an unregistered key counts for nothing.
   - An approval for another request id or another account does not verify (it is bound to both).
4. Released only if valid roles >= 2. Release is logged in the hash-chained audit log.

Demo note: here FairRun generates all three keys so the demo can play every party. In production each
party holds only its own private key (e.g. on its own device); FairRun stores only public keys.
"""
from __future__ import annotations

import json
import secrets
import time

from .crypto import HybridSigner, verify_signature
from .fraud import blind_index

ROLES = ("employer", "platform", "contractor")
ROLE_TEXT = {"employer": "Employer's payroll admin",
             "platform": "Platform call-back to the phone on file",
             "contractor": "Contractor's own login"}
DOMAIN = b"fairrun-bank-change/v1|"


def request_message(req: dict) -> bytes:
    return DOMAIN + json.dumps(req, sort_keys=True).encode()


class ApprovalQuorum:
    def __init__(self, threshold: int = 2, signers: dict | None = None):
        self.signers = signers or {r: HybridSigner.generate() for r in ROLES}
        self.public = {r: s.public() for r, s in self.signers.items()}       # all FairRun needs in production
        self.threshold = threshold
        self.requests: dict[tuple[str, str], dict] = {}                      # (employer, contractor) -> state

    # -- opening and signing -------------------------------------------------
    def open(self, employer_id: str, contractor_id: str, new_account: str) -> dict:
        """Open (or reuse) the request for this exact change. A different new account = a new request."""
        idx = blind_index(new_account)
        cur = self.requests.get((employer_id, contractor_id))
        if cur and cur["req"]["account_index"] == idx:
            return cur["req"]
        req = {"id": secrets.token_hex(8), "employer": employer_id, "contractor": contractor_id,
               "account_index": idx, "opened": round(time.time(), 3)}
        self.requests[(employer_id, contractor_id)] = {"req": req, "sigs": []}
        return req

    def sign_as(self, role: str, req: dict, signer: HybridSigner | None = None) -> dict:
        """What one party's device does: sign the exact request. `signer` lets an attacker use their own key."""
        return {"role": role, "sig": (signer or self.signers[role]).sign(request_message(req))}

    def submit(self, employer_id: str, contractor_id: str, approval: dict) -> None:
        self.requests[(employer_id, contractor_id)]["sigs"].append(approval)

    def approve(self, employer_id: str, contractor_id: str, role: str) -> None:
        st = self.requests[(employer_id, contractor_id)]
        self.submit(employer_id, contractor_id, self.sign_as(role, st["req"]))

    # -- checking -------------------------------------------------------------
    def status(self, employer_id: str, contractor_id: str, current_account: str) -> dict:
        st = self.requests.get((employer_id, contractor_id))
        if st is None:
            return {"released": False, "valid": [], "rejected": [], "need": self.threshold,
                    "why": "no approval request"}
        req = st["req"]
        if req["account_index"] != blind_index(current_account):
            return {"released": False, "valid": [], "rejected": [], "need": self.threshold,
                    "why": "approvals are for a different bank account"}
        msg = request_message(req)
        valid, rejected = [], []
        for a in st["sigs"]:
            role = a.get("role") if isinstance(a, dict) else None
            if not isinstance(role, str):
                rejected.append("malformed approval ignored")
                continue
            try:                                             # a broken approval is a "no", never a crash
                good = role in self.public and verify_signature(self.public[role], msg, a.get("sig"))
            except Exception:
                good = False
            if good:
                if role not in valid:
                    valid.append(role)                       # one role, one vote: repeats count once
                else:
                    rejected.append(f"{role}: repeated approval, counted once")
            else:
                rejected.append(f"{role}: signature invalid for this request")
        ok = len(valid) >= self.threshold
        return {"released": ok, "valid": valid, "rejected": rejected, "need": self.threshold,
                "request": req["id"],
                "why": f"{len(valid)} of {len(ROLES)} approvals valid, {self.threshold} needed"}


BANK_CHANGE_REASONS = ("bank details changed since last run", "message asks to change bank details",
                       "new payee since last run")


def only_bank_change(reason: str) -> bool:
    """A quorum can release a bank-change or new-payee hold, never a hold for other reasons (e.g. shared accounts)."""
    parts = [p.strip() for p in reason.split(";") if p.strip()]
    return bool(parts) and all(any(p.startswith(b) for b in BANK_CHANGE_REASONS) for p in parts)
