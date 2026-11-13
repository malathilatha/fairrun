"""Create the demo contractors as Airwallex beneficiaries, each under ITS OWN employer.

    python scripts\\beneficiaries.py validate     # dry run: Airwallex checks every payload, creates nothing
    python scripts\\beneficiaries.py create       # create the ones that validated (skips ones already saved)
    python scripts\\beneficiaries.py list         # show saved beneficiary ids

Corridors follow the builder guide:
  US / USD / LOCAL : ABA routing + account number + bank_account_category "Checking"
  GB / GBP / LOCAL : sort_code (lowercase) + account number + bank_name
  DE / EUR / SWIFT : IBAN + swift_code
Routing codes and IBANs are valid public test values; names and account holders are synthetic.
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

US_ADDR = {"street_address": "200 Congress Ave", "city": "Austin", "state": "TX", "postcode": "78701",
           "country_code": "US"}

# contractor_id -> (employer, first, last, address, method, bank_details)
CONTRACTORS = {
    "alpha-anna": ("alpha", "Anna", "Becker",
                   {"street_address": "Friedrichstrasse 10", "city": "Berlin", "postcode": "10117",
                    "country_code": "DE"}, "SWIFT",
                   {"account_currency": "EUR", "bank_country_code": "DE",
                    "iban": "DE89370400440532013000", "swift_code": "COBADEFFXXX"}),
    "alpha-jonas": ("alpha", "Jonas", "Weber",
                    {"street_address": "Marienplatz 1", "city": "Munich", "postcode": "80331",
                     "country_code": "DE"}, "SWIFT",
                    {"account_currency": "EUR", "bank_country_code": "DE",
                     "iban": "DE02120300000000202051", "swift_code": "BYLADEM1001"}),
    "alpha-mike": ("alpha", "Mike", "Carter", US_ADDR, "LOCAL",
                   {"account_currency": "USD", "bank_country_code": "US", "account_number": "000123456789",
                    "account_routing_type1": "aba", "account_routing_value1": "026009593",
                    "bank_account_category": "Checking"}),
    "bright-tom": ("bright", "Tom", "Hughes",
                   {"street_address": "1 Park Row", "city": "Leeds", "postcode": "LS1 5AB",
                    "country_code": "GB"}, "LOCAL",
                   {"account_currency": "GBP", "bank_country_code": "GB", "account_number": "70872490",
                    "account_routing_type1": "sort_code", "account_routing_value1": "404784",
                    "bank_name": "HSBC UK"}),
    "bright-sara": ("bright", "Sara", "Price",
                    {"street_address": "10 Stonegate", "city": "York", "postcode": "YO1 8AS",
                     "country_code": "GB"}, "LOCAL",
                    {"account_currency": "GBP", "bank_country_code": "GB", "account_number": "55779911",
                     "account_routing_type1": "sort_code", "account_routing_value1": "200000",
                     "bank_name": "Barclays"}),
    "cedar-lee": ("cedar", "Lee", "Morgan",
                  {"street_address": "1600 Broadway", "city": "Denver", "state": "CO", "postcode": "80202",
                   "country_code": "US"}, "LOCAL",
                  {"account_currency": "USD", "bank_country_code": "US", "account_number": "000987654321",
                   "account_routing_type1": "aba", "account_routing_value1": "026009593",
                   "bank_account_category": "Checking"}),
    "cedar-ria": ("cedar", "Ria", "Shah",
                  {"street_address": "400 Pine St", "city": "Seattle", "state": "WA", "postcode": "98101",
                   "country_code": "US"}, "LOCAL",
                  {"account_currency": "USD", "bank_country_code": "US", "account_number": "000555000111",
                   "account_routing_type1": "aba", "account_routing_value1": "026009593",
                   "bank_account_category": "Checking"}),
}


def token() -> dict:
    r = requests.post(f"{BASE}/authentication/login", timeout=20, headers={
        "x-client-id": os.environ["AWX_CLIENT_ID"], "x-api-key": os.environ["AWX_API_KEY"]})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['token']}"}


def call(h, path, acct, body):
    r = requests.post(f"{BASE}{path}", headers=dict(h, **{"x-on-behalf-of": acct}), json=body, timeout=30)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"raw": r.text[:300]}


def load() -> dict:
    return json.load(open(STATE))


def save(s) -> None:
    json.dump(s, open(STATE, "w"), indent=2)


def payload(cid: str) -> dict:
    _, first, last, addr, method, bank = CONTRACTORS[cid]
    return {
        "beneficiary": {
            "entity_type": "PERSONAL",
            "first_name": first, "last_name": last,
            "address": addr,
            "bank_details": dict(bank, account_name=f"{first} {last}"),
        },
        "transfer_methods": [method],
        "nickname": cid,
    }


def validate() -> None:
    h, state = token(), load()
    ok = 0
    for cid, (emp, *_rest) in CONTRACTORS.items():
        code, body = call(h, "/beneficiaries/validate", state[emp]["id"], payload(cid))
        if code < 300:
            ok += 1
            print(f"OK    {cid:12} under {emp}")
        else:
            print(f"FAIL  {cid:12} under {emp}: HTTP {code} {body.get('code')} - {body.get('message', '')[:200]}"
                  f"  [field: {body.get('source', '?')}]")
    print(f"\n{ok}/{len(CONTRACTORS)} valid. Send me any FAIL lines; run `create` when all are OK.")


def create() -> None:
    h, state = token(), load()
    for cid, (emp, *_rest) in CONTRACTORS.items():
        bens = state[emp].setdefault("beneficiaries", {})
        if cid in bens:
            print(f"skip  {cid:12} already {bens[cid]}")
            continue
        body_in = dict(payload(cid), request_id=str(uuid.uuid4()))
        code, body = call(h, "/beneficiaries/create", state[emp]["id"], body_in)
        bid = body.get("id") or body.get("beneficiary_id")
        if code < 300 and bid:
            bens[cid] = bid
            save(state)                      # saved immediately, so a rerun never duplicates
            print(f"made  {cid:12} -> {bid}")
        else:
            print(f"FAIL  {cid:12}: HTTP {code} {json.dumps(body)[:300]}")


def list_saved() -> None:
    for emp, rec in load().items():
        for cid, bid in rec.get("beneficiaries", {}).items():
            print(f"{emp:7} {cid:12} {bid}")


if __name__ == "__main__":
    cmds = {"validate": validate, "create": create, "list": list_saved}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        sys.exit(__doc__)
    cmds[sys.argv[1]]()
