"""Check your Airwallex sandbox connection and whether platform access is enabled.

PowerShell:
    $env:AWX_CLIENT_ID="..."; $env:AWX_API_KEY="..."
    python scripts/check_sandbox.py
"""
import os
import sys

import requests

BASE = "https://api.sandbox.airwallex.com/api/v1"

missing = [k for k in ("AWX_CLIENT_ID", "AWX_API_KEY") if not os.environ.get(k)]
if missing:
    sys.exit(f"Set these environment variables first: {', '.join(missing)}")

r = requests.post(f"{BASE}/authentication/login", timeout=20, headers={
    "x-client-id": os.environ["AWX_CLIENT_ID"], "x-api-key": os.environ["AWX_API_KEY"]})
if not r.ok:   # Airwallex login returns 201
    sys.exit(f"Login failed ({r.status_code}): {r.text[:200]}")
h = {"Authorization": f"Bearer {r.json()['token']}"}
print("1. Login OK")

bal = requests.get(f"{BASE}/balances/current", headers=h, timeout=20)
if bal.ok:
    print("2. Balances:", ", ".join(f"{b['currency']} {b['available_amount']}" for b in bal.json()[:6]))
else:
    print(f"2. Balances failed (HTTP {bal.status_code}): {bal.text[:200]}")
    print("   If this is a permission error, add 'Balances: Read' to your scoped key.")

acc = requests.get(f"{BASE}/accounts", headers=h, timeout=20)
print(f"3. Connected accounts endpoint: HTTP {acc.status_code}")
if acc.ok:
    items = acc.json().get("items", [])
    print(f"   Listing works ({len(items)} connected accounts so far).")
    print("   Note: listing can work even before onboarding is enabled.")
    print("   The real test is creating one; the error 'cannot onboard business accounts'")
    print("   means platform access is still OFF.")
else:
    print("   ", acc.text[:200])
