"""Rebuild employers_sandbox.json from Airwallex itself (read-only: creates nothing).

Use when the local file was lost. It finds the existing connected accounts by business name,
then each one's wallet (Global Account) and contractor beneficiaries (matched by nickname).

    python scripts\\recover_state.py
"""
from __future__ import annotations

import json
import os
import sys

import requests

BASE = "https://api.sandbox.airwallex.com/api/v1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "employers_sandbox.json")

NAMES = {"alpha": "Alpha Studio Sandbox LLC", "bright": "Bright Bakery Sandbox LLC",
         "cedar": "Cedar Labs Sandbox LLC"}
CURRENCY = {"alpha": "USD", "bright": "GBP", "cedar": "USD"}


def token() -> dict:
    r = requests.post(f"{BASE}/authentication/login", timeout=20, headers={
        "x-client-id": os.environ["AWX_CLIENT_ID"], "x-api-key": os.environ["AWX_API_KEY"]})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['token']}"}


def get(h, path, acct=None, **params):
    headers = dict(h, **({"x-on-behalf-of": acct} if acct else {}))
    r = requests.get(f"{BASE}{path}", headers=headers, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    return data.get("items", data if isinstance(data, list) else [])


def business_name(acct: dict) -> str:
    return (((acct.get("account_details") or {}).get("business_details") or {}).get("business_name")
            or acct.get("nickname") or "")


def main():
    if os.path.exists(STATE):
        sys.exit(f"{STATE} already exists - nothing to recover.")
    h = token()
    accounts = get(h, "/accounts", page_size=100)
    print(f"Found {len(accounts)} connected accounts on Airwallex.")
    state = {}
    for key, name in NAMES.items():
        matches = [a for a in accounts if business_name(a) == name]
        if not matches:
            print(f"  {key:7} NOT FOUND (looked for '{name}')")
            continue
        active = [a for a in matches if a.get("status") == "ACTIVE"] or matches
        acct = active[0]
        if len(matches) > 1:
            print(f"  {key:7} {len(matches)} accounts named '{name}' - using the ACTIVE one {acct['id']}")
        rec = {"id": acct["id"], "status": acct.get("status")}

        wallets = get(h, "/global_accounts", acct["id"])
        want = [w for w in wallets if CURRENCY[key] in json.dumps(w)]
        if want:
            rec["global_account_id"] = want[0]["id"]

        bens = get(h, "/beneficiaries", acct["id"], page_size=100)
        rec["beneficiaries"] = {b["nickname"]: (b.get("beneficiary_id") or b.get("id"))
                                for b in bens if b.get("nickname", "").startswith(key + "-")}
        state[key] = rec
        print(f"  {key:7} {rec['id']} {rec['status']}  wallet={rec.get('global_account_id', 'none')}  "
              f"contractors={sorted(rec['beneficiaries'])}")

    json.dump(state, open(STATE, "w"), indent=2)
    print(f"\nSaved {STATE}. Check that all three employers and 7 contractors are listed above.")


if __name__ == "__main__":
    main()
