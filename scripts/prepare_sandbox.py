"""Prepare the three ACTIVE employer accounts for the FairRun demo, safely and repeatably.

    python scripts\\prepare_sandbox.py wallets     # one Global Account per employer (USD / GBP / USD)
    python scripts\\prepare_sandbox.py fund        # top each wallet up to its demo balance (never double-funds)
    python scripts\\prepare_sandbox.py balances    # read each employer's own balances
    python scripts\\prepare_sandbox.py ready       # tiny FX test: is fee setup finished yet?

All calls act ON BEHALF OF one employer (x-on-behalf-of), never the platform wallet.
Deposit simulation has no request_id, so `fund` re-reads the balance first and only tops up the gap.
"""
from __future__ import annotations

import json
import os
import sys
import uuid

import requests

BASE = "https://api.sandbox.airwallex.com/api/v1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "employers_sandbox.json")

# Same story as the demo: Bright is deliberately short; Cedar's main deposit arrives later.
PLAN = {
    "alpha":  {"currency": "USD", "country": "US", "target": 15000},
    "bright": {"currency": "GBP", "country": "GB", "target": 1200},
    "cedar":  {"currency": "USD", "country": "US", "target": 2000},
}


def token() -> dict:
    r = requests.post(f"{BASE}/authentication/login", timeout=20, headers={
        "x-client-id": os.environ["AWX_CLIENT_ID"], "x-api-key": os.environ["AWX_API_KEY"]})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['token']}"}


def call(h, method, path, acct, **kw):
    headers = dict(h, **{"x-on-behalf-of": acct})
    r = requests.request(method, f"{BASE}{path}", headers=headers, timeout=30, **kw)
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:300]}
    return r.status_code, body


def load() -> dict:
    if not os.path.exists(STATE):
        sys.exit("employers_sandbox.json not found - run onboard_employers.py first.")
    return json.load(open(STATE))


def save(s: dict) -> None:
    json.dump(s, open(STATE, "w"), indent=2)


def balance(h, acct, cur) -> float:
    code, body = call(h, "GET", "/balances/current", acct)
    if code >= 300:
        raise RuntimeError(f"balances failed HTTP {code}: {body}")
    return next((float(b["available_amount"]) for b in body if b["currency"] == cur), 0.0)


def wallets() -> None:
    h, state = token(), load()
    for key, cfg in PLAN.items():
        rec = state[key]
        if rec.get("global_account_id"):
            print(f"{key:7} wallet exists: {rec['global_account_id']}")
            continue
        code, body = call(h, "GET", "/global_accounts", rec["id"])
        existing = [g for g in body.get("items", []) if g.get("currency") == cfg["currency"]
                    or cfg["currency"] in json.dumps(g.get("required_features", ""))] if code < 300 else []
        if existing:
            rec["global_account_id"] = existing[0]["id"]
            print(f"{key:7} found existing wallet {existing[0]['id']}")
        else:
            code, body = call(h, "POST", "/global_accounts/create", rec["id"], json={
                "request_id": str(uuid.uuid4()), "country_code": cfg["country"],
                "required_features": [{"currency": cfg["currency"], "transfer_method": "LOCAL"}]})
            if code >= 300:
                print(f"{key:7} wallet FAILED HTTP {code}: {json.dumps(body)[:400]}")
                continue
            rec["global_account_id"] = body["id"]
            print(f"{key:7} created {cfg['currency']} wallet {body['id']}")
        save(state)


def fund() -> None:
    h, state = token(), load()
    for key, cfg in PLAN.items():
        rec = state[key]
        if not rec.get("global_account_id"):
            print(f"{key:7} no wallet yet - run `wallets` first")
            continue
        have = balance(h, rec["id"], cfg["currency"])
        gap = round(cfg["target"] - have, 2)
        if gap <= 0:
            print(f"{key:7} already has {have:,.2f} {cfg['currency']} (target {cfg['target']:,}) - no deposit")
            continue
        code, body = call(h, "POST", "/simulation/deposit/create", rec["id"], json={
            "global_account_id": rec["global_account_id"], "amount": gap, "payer_name": "FairRun demo funding"})
        if code >= 300:
            print(f"{key:7} deposit FAILED HTTP {code}: {json.dumps(body)[:400]}")
            continue
        now = balance(h, rec["id"], cfg["currency"])
        print(f"{key:7} deposited {gap:,.2f} {cfg['currency']} -> balance {now:,.2f}")


def balances() -> None:
    h, state = token(), load()
    for key, cfg in PLAN.items():
        code, body = call(h, "GET", "/balances/current", state[key]["id"])
        rows = ", ".join(f"{b['currency']} {float(b['available_amount']):,.2f}" for b in body
                         if float(b.get("available_amount", 0))) if code < 300 else f"HTTP {code} {body}"
        print(f"{key:7} {rows or '(all zero)'}")


def ready() -> None:
    """Convert 10 EUR from USD in Alpha's wallet. Success means fee setup is done for FX."""
    h, state = token(), load()
    acct = state["alpha"]["id"]
    code, body = call(h, "POST", "/fx/conversions/create", acct, json={
        "request_id": str(uuid.uuid4()), "buy_currency": "EUR", "sell_currency": "USD", "buy_amount": "10.00"})
    if code < 300:
        print(f"READY: FX works for Alpha (status {body.get('status')}). Payouts should work too.")
    elif "unconfigured_client_fee" in json.dumps(body) or "fee" in json.dumps(body).lower():
        print("NOT READY YET: Airwallex is still setting up fees for new accounts. Try again in an hour.")
        print(f"  ({body.get('code')}: {body.get('message')})")
    else:
        print(f"FX test failed HTTP {code}: {json.dumps(body)[:500]}")


if __name__ == "__main__":
    cmds = {"wallets": wallets, "fund": fund, "balances": balances, "ready": ready}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        sys.exit(__doc__)
    cmds[sys.argv[1]]()
