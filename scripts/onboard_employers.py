"""Create the three FairRun employers as Airwallex connected accounts, safely, one at a time.

Safety rules (from the builder guide and Slack):
- Create each employer ONCE. Its acct_ id is saved to employers_sandbox.json immediately and reused.
- Missing fields are fixed with /update on the SAME account before submit (fields lock after submit).
- Never auto-create a second account for the same employer.
- New accounts may need minutes to days before FX/payouts work (fee configuration), so onboard early.

Usage (Command Prompt, venv active, AWX_CLIENT_ID / AWX_API_KEY set):
    python scripts\\onboard_employers.py categories          # list valid industry category codes
    python scripts\\onboard_employers.py show alpha          # print the payload, send nothing
    python scripts\\onboard_employers.py create alpha        # create (or reuse) + submit + activate
    python scripts\\onboard_employers.py fix alpha           # resend business details to the SAME account
    python scripts\\onboard_employers.py status              # status of all saved employers
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid

import requests

BASE = "https://api.sandbox.airwallex.com/api/v1"
STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "employers_sandbox.json")

# Synthetic demo companies. EINs are made-up placeholders in valid format; nothing here is a real entity.
EMPLOYERS = {
    "alpha":  {"name": "Alpha Studio Sandbox LLC",  "ein": "12-3456781", "desc": "Design studio paying freelance designers",
               "revenue": ("50000", "USD")},
    "bright": {"name": "Bright Bakery Sandbox LLC", "ein": "12-3456782", "desc": "Bakery paying delivery contractors",
               "revenue": ("20000", "GBP")},
    "cedar":  {"name": "Cedar Labs Sandbox LLC",    "ein": "12-3456783", "desc": "Software lab paying contract developers",
               "revenue": ("80000", "USD")},
}
ADDRESS = {"address_line1": "100 Market Street", "suburb": "San Francisco", "state": "CA",
           "postcode": "94105", "country_code": "US"}            # account addresses use address_line1 + suburb
INDUSTRY_CODE = os.environ.get("FAIRRUN_INDUSTRY_CODE", "")       # ICCV3_xxxxxx from `categories`


def token() -> dict:
    r = requests.post(f"{BASE}/authentication/login", timeout=20, headers={
        "x-client-id": os.environ["AWX_CLIENT_ID"], "x-api-key": os.environ["AWX_API_KEY"]})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['token']}"}


def call(h, method, path, **kw):
    r = requests.request(method, f"{BASE}{path}", headers=h, timeout=30, **kw)
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:300]}
    return r.status_code, body


def load_state() -> dict:
    return json.load(open(STATE)) if os.path.exists(STATE) else {}


def save_state(s: dict) -> None:
    json.dump(s, open(STATE, "w"), indent=2)


def payload(key: str) -> dict:
    e = EMPLOYERS[key]
    person = {
        "first_name": "Priya", "last_name": "Demo", "date_of_birth": "1985-04-12",
        "email": f"owner.{key}@example.com", "nationality": "US",
        "roles": ["BENEFICIAL_OWNER", "DIRECTOR", "AUTHORISED_PERSON"],
        "residential_address": ADDRESS,
        "identifications": {"primary": {"identification_type": "PASSPORT", "issuing_country_code": "US",
                                        "passport": {"number": "X12345678", "expiry_date": "2032-01-01"}}},
    }
    business = {
        "business_name": e["name"],
        "business_structure": "COMPANY",
        "registration_address": ADDRESS,
        "business_address": ADDRESS,
        "business_identifiers": [{"country_code": "US", "type": "EIN", "number": e["ein"]}],
        "description_of_goods_or_services": e["desc"],
        "operating_country": ["US"],
        "url": f"https://{key}.example.com",
        "account_usage": {
            "product_reference": ["MAKE_TRANSFERS", "CONVERT_FUNDS", "RECEIVE_TRANSFERS"],
            "estimated_monthly_revenue": {"amount": e["revenue"][0], "currency": e["revenue"][1]},
        },
    }
    if INDUSTRY_CODE:
        business["industry_category_code"] = INDUSTRY_CODE
    return {
        "request_id": str(uuid.uuid4()),
        "primary_contact": {"email": f"owner.{key}@example.com"},
        "customer_agreements": {"agreed_to_data_usage": True, "agreed_to_terms_and_conditions": True},
        "account_details": {"business_details": business, "business_person_details": [person]},
    }


def create(key: str) -> None:
    h = token()
    state = load_state()
    acct = state.get(key, {}).get("id")

    if not acct:
        body = payload(key)
        code, resp = call(h, "POST", "/accounts/create", json=body)
        print(f"create {key}: HTTP {code}")
        if code >= 300 or "id" not in resp:
            print(json.dumps(resp, indent=2)[:1500])
            print("\nNOT created. Fix the payload (send me this error) and run again - nothing was saved.")
            return
        acct = resp["id"]
        state[key] = {"id": acct, "status": resp.get("status")}
        save_state(state)                         # saved BEFORE anything else can fail
        print(f"  created {acct} (status {resp.get('status')}), saved to {os.path.basename(STATE)}")
    else:
        print(f"{key}: reusing existing {acct}")

    code, resp = call(h, "POST", f"/accounts/{acct}/submit", json={})
    print(f"submit {acct}: HTTP {code}")
    if code >= 300:
        print(json.dumps(resp, indent=2)[:1500])
        print("\nSubmit refused. The account still exists and is NOT locked: send me this error and we will "
              "fix it with /update on this same account. Do NOT create a new one.")
        return

    time.sleep(3)
    code, resp = call(h, "POST", f"/simulation/accounts/{acct}/update_status",
                      json={"next_status": "ACTIVE", "force": True})
    print(f"activate {acct}: HTTP {code} {resp.get('status', '') if isinstance(resp, dict) else ''}")
    code, resp = call(h, "GET", f"/accounts/{acct}")
    status = resp.get("status")
    state[key]["status"] = status
    save_state(state)
    print(f"  {key} is now {status}. Wait a few minutes (possibly longer) before the first FX or payout.")


def fix(key: str) -> None:
    """Re-send business_details (with the current payload) to the SAME account, before submit.
    Business persons are not re-sent: the guide says they only persist from the create call."""
    h = token()
    acct = load_state()[key]["id"]
    biz = payload(key)["account_details"]["business_details"]
    code, resp = call(h, "POST", f"/accounts/{acct}/update",
                      json={"request_id": str(uuid.uuid4()), "account_details": {"business_details": biz}})
    print(f"update {acct}: HTTP {code}")
    if code >= 300:
        print(json.dumps(resp, indent=2)[:1500])
        return
    usage = (resp.get("account_details", {}).get("business_details", {}) or {}).get("account_usage")
    print(f"  account_usage now: {usage}")
    print(f"  Now run:  python scripts\\onboard_employers.py create {key}   (reuses {acct}, submits)")


def update(key: str, patch_file: str) -> None:
    """Fix a created-but-not-submitted account: send a JSON patch file to /update."""
    h = token()
    acct = load_state()[key]["id"]
    patch = json.load(open(patch_file))
    code, resp = call(h, "POST", f"/accounts/{acct}/update", json=patch)
    print(f"update {acct}: HTTP {code}")
    print(json.dumps(resp, indent=2)[:1500])


def status() -> None:
    h = token()
    for key, rec in load_state().items():
        code, resp = call(h, "GET", f"/accounts/{rec['id']}")
        print(f"{key:7} {rec['id']}  {resp.get('status', code)}")


def _find_codes(node, path=""):
    """Walk any JSON shape and yield (code, label) for every ICCV3_ code found."""
    if isinstance(node, dict):
        code = next((v for v in node.values() if isinstance(v, str) and v.startswith("ICCV3_")), None)
        if code:
            label = " / ".join(str(node.get(k)) for k in ("name", "description", "label", "industry", "category")
                               if node.get(k)) or path
            yield code, label
        for k, v in node.items():
            name = node.get("name") or node.get("category") or ""
            yield from _find_codes(v, f"{path} > {name}".strip(" >") if name else path)
    elif isinstance(node, list):
        for item in node:
            yield from _find_codes(item, path)


def categories() -> None:
    h = token()
    code, resp = call(h, "GET", "/reference/industry_categories")
    print(f"HTTP {code}")
    found = list(dict.fromkeys(_find_codes(resp)))
    if not found:
        print("No ICCV3_ codes found. First part of the raw response:")
        print(json.dumps(resp, indent=1)[:1500])
        return
    words = ("software", "design", "bakery", "food", "consult", "computer", "information", "technology")
    likely = [(c, l) for c, l in found if any(w in l.lower() for w in words)]
    for c, l in (likely or found)[:40]:
        print(f"{c}   {l[:110]}")
    print(f"\n{len(found)} codes total; showing {'likely matches' if likely else 'the first 40'}.")
    print("Pick one and run:  set FAIRRUN_INDUSTRY_CODE=ICCV3_xxxxxx")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in {"categories", "show", "create", "fix", "update", "status"}:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "categories":
        categories()
    elif cmd == "status":
        status()
    elif cmd == "show":
        print(json.dumps(payload(sys.argv[2]), indent=2))
    elif cmd == "create":
        create(sys.argv[2])
    elif cmd == "fix":
        fix(sys.argv[2])
    elif cmd == "update":
        update(sys.argv[2], sys.argv[3])
