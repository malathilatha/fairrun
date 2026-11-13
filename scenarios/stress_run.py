"""Head-to-head stress test from the terminal.

Run:  python -m scenarios.stress_run [cases] [seed]
"""
from __future__ import annotations

import sys

from fairrun.baseline import METRICS, stress_test


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 2026
    r = stress_test(n, seed)
    t, f = r["typical"], r["fairrun"]
    print(f"{n} random cases, seed {seed}, {t.get('paydays', 0)} paydays. Trouble injected: {r['trouble']}")
    print(f"{'':52}{'Typical':>10}{'FairRun':>10}")
    for key, label in METRICS + [("correct_payments", "Workers paid correctly")]:
        print(f"{label:52}{t.get(key, 0):>10}{f.get(key, 0):>10}")
    print(f"FairRun: {f.get('fr_PAID_FULL', 0)} paid in full, {f.get('fr_PAID_PARTIAL', 0)} fair partial runs, "
          f"{f.get('fr_replays_blocked', 0)} replays blocked, {f.get('fr_held', 0)} payouts held.")


if __name__ == "__main__":
    main()
