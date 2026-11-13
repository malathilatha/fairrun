"""A 'typical payroll agent' baseline, a referee, and a head-to-head random stress test.

The baseline is OUR OWN simple agent, not a real product. It behaves the way a payroll agent does when
an AI model is simply handed payment tools and no independent controls:

  - it adds up ALL wallets and approves if the platform as a whole has enough money;
  - when the employer's own wallet is short, it tops it up from other employers' wallets;
  - after a timeout it retries with a new request id (it does not look the transfer up first);
  - it has no memory of batches, so a replayed batch is paid again;
  - it accepts changed bank details;
  - its money check is total-only (total held >= total owed).

Both agents run on identical copies of the same world. A neutral `Referee` measures what really happened
from the (mock) Airwallex records, not from what either agent reports about itself.
"""
from __future__ import annotations

import dataclasses
import itertools
import random
import secrets
from collections import Counter

from . import agent as agent_module
from .airwallex_mock import RATES, AirwallexError, AmbiguousTimeout, MockAirwallex
from .engine import PLATFORM_ACCOUNT, FairRun
from .models import Contractor, Employer, to_minor
from .pricing import price_plan
from .solvency import FundsBook, check_segregation, pooled_check


# ---------------------------------------------------------------------------
# A mock that remembers who was paid (the referee's source of truth)
# ---------------------------------------------------------------------------
class WatchedMock(MockAirwallex):
    def __init__(self):
        super().__init__()
        self.payments: list[dict] = []

    def create_transfer(self, account, request_id, currency, amount, fee, **kw):
        rec = {"account": account, "contractor": kw.get("contractor_id"), "currency": currency, "amount": amount}
        try:
            t = super().create_transfer(account, request_id, currency, amount, fee, **kw)
        except AmbiguousTimeout:
            self.payments.append(rec)             # Airwallex accepted it before the network failed
            raise
        self.payments.append(rec)
        return t


def clone_world(aw: MockAirwallex, employers: list[Employer]) -> tuple[WatchedMock, list[Employer]]:
    """An independent copy of balances, transfers and employers, so two agents never share state."""
    new = WatchedMock()
    new.balances = {a: dict(b) for a, b in aw.balances.items()}
    new.transfers = {k: dataclasses.replace(t) for k, t in aw.transfers.items()}
    new.charges = [dict(c) for c in aw.charges]
    new.seen_request_ids = set(aw.seen_request_ids)
    new._ids = itertools.count(len(aw.transfers) + 1000)
    new.fail_next_timeout_after_accept = aw.fail_next_timeout_after_accept
    return new, [Employer(e.employer_id, e.name, e.wallet_currency, list(e.contractors)) for e in employers]


def fx(amount: int, a: str, b: str) -> int:
    """Value of `amount` of currency a, in currency b (demo rates), rounded down."""
    if a == b:
        return amount
    if (a, b) in RATES:
        return int(amount * RATES[(a, b)])
    return fx(fx(amount, a, "USD"), "USD", b)


# ---------------------------------------------------------------------------
# The baseline agent
# ---------------------------------------------------------------------------
class TypicalAgent:
    def __init__(self, client):
        self.client = client

    @staticmethod
    def _rid() -> str:
        return "typ_" + secrets.token_hex(6)       # a fresh id every time: retries are not idempotent

    def run_employer(self, employer: Employer, period: str, all_employers: list[Employer]) -> dict:
        acct, wc = employer.employer_id, employer.wallet_currency
        plan = price_plan(employer, period)
        out = {"status": "PAID", "paid": [], "borrowed": [], "retried": [], "failed": [], "notes": []}
        own = self.client.get_balances(acct).get(wc, 0)
        others = [e for e in all_employers if e.employer_id != acct]
        pool = own + sum(fx(self.client.get_balances(o.employer_id).get(o.wallet_currency, 0),
                            o.wallet_currency, wc) for o in others)
        out["notes"].append(f"All wallets together are worth {pool / 100:,.2f} {wc}; payroll costs "
                            f"{plan.wallet_cost / 100:,.2f} {wc}.")
        if pool < plan.wallet_cost:
            out["status"] = "FAILED"
            out["notes"].append("Not enough money on the whole platform: nobody is paid.")
            return out
        if own < plan.wallet_cost:
            need = plan.wallet_cost - own
            for o in sorted(others, key=lambda e: -fx(self.client.get_balances(e.employer_id)
                                                      .get(e.wallet_currency, 0), e.wallet_currency, wc)):
                if need <= 0:
                    break
                have = self.client.balances[o.employer_id].get(o.wallet_currency, 0)
                take_wc = min(need, fx(have, o.wallet_currency, wc))
                if take_wc <= 0:
                    continue
                take = have if take_wc == fx(have, o.wallet_currency, wc) else min(
                    have, fx(take_wc, wc, o.wallet_currency) + 1)
                self.client.balances[o.employer_id][o.wallet_currency] = have - take
                self.client.balances[acct][wc] = self.client.balances[acct].get(wc, 0) + take_wc
                out["borrowed"].append((o.employer_id, take, o.wallet_currency))
                need -= take_wc
        for cur, need in plan.conversions.items():
            if cur != wc:
                try:
                    self.client.convert(acct, self._rid(), wc, cur, need)
                except AirwallexError as e:
                    out["notes"].append(f"FX to {cur} failed: {e.code}.")
        for p in plan.payouts:
            try:
                self.client.create_transfer(acct, self._rid(), p.currency, p.amount, p.fee,
                                            contractor_id=p.contractor_id, method=p.method)
                out["paid"].append(p.contractor_id)
            except AmbiguousTimeout:
                out["paid"].append(p.contractor_id)
                try:                                  # "it timed out, send it again"
                    if p.currency != wc and self.client.get_balances(acct).get(p.currency, 0) < p.amount + p.fee:
                        self.client.convert(acct, self._rid(), wc, p.currency, p.amount + p.fee)   # "top it up"
                    self.client.create_transfer(acct, self._rid(), p.currency, p.amount, p.fee,
                                                contractor_id=p.contractor_id, method=p.method)
                    out["retried"].append(p.contractor_id)
                except AirwallexError:
                    out["notes"].append(f"Retry for {p.contractor_id} failed: wallet empty.")
            except AirwallexError as e:
                out["failed"].append(p.contractor_id)
        try:
            self.client.create_charge(acct, PLATFORM_ACCOUNT, self._rid(), wc, plan.platform_fee)
        except AirwallexError:
            out["notes"].append("Platform fee could not be collected.")
        return out


def describe_typical(out: dict, employer: Employer, names: dict[str, str], replay: bool = False,
                     attackers: tuple[str, ...] = ()) -> list[str]:
    """Plain-English list of what went wrong in a baseline run (empty if nothing did)."""
    amount = {c.contractor_id: (c.amount, c.currency) for c in employer.contractors}
    issues = []
    if out["status"] == "FAILED":
        issues.append("Nobody was paid: it only looked at the platform total, found too little, and stopped. "
                      "No fair split, no escalation.")
    for acct, take, cur in out["borrowed"]:
        issues.append(f"Took {take / 100:,.2f} {cur} from {names.get(acct, acct)}'s wallet to pay "
                      f"{employer.name}'s workers.")
    for cid in out["retried"]:
        a, cur = amount[cid]
        issues.append(f"Paid {cid} twice after the timeout ({a / 100:,.2f} {cur} extra).")
    if replay and out["paid"]:
        issues.append(f"Paid the same batch a second time: {len(out['paid'])} workers paid again.")
    for cid in attackers:
        if cid in out["paid"]:
            a, cur = amount[cid]
            issues.append(f"Sent {cid}'s {a / 100:,.2f} {cur} to the changed bank account, with no check.")
    return issues


def run_custom(spec: dict) -> dict:
    """A case the viewer designs: their balances, pay amounts and trouble, through both agents.
    spec = {balances: {acct: major}, amounts: {contractor: major}, employer: acct, timeout: bool,
            replay: bool, pirate: contractor id or None, move: (src, dst, major) or None}"""
    result = {}
    for who in ("typical", "fairrun"):
        aw = WatchedMock()
        aw.open_account(PLATFORM_ACCOUNT)
        employers = []
        for acct, name, wc, people in _BASE:
            cs = [Contractor(cid, cid, cur, to_minor(spec["amounts"].get(cid, amt)), method, bank, "XX")
                  for cid, cur, amt, method, bank in people]
            employers.append(Employer(acct, name, wc, cs))
            aw.open_account(acct)
            aw.simulate_deposit(acct, wc, to_minor(spec["balances"][acct]))
        by_id = {e.employer_id: e for e in employers}
        names = {e.employer_id: e.name for e in employers}
        emp = by_id[spec["employer"]]
        ref = Referee(aw, employers)
        out = {"lines": [], "issues": [], "status": "", "move": None}
        book = FundsBook.snapshot(aw, list(by_id))             # the records before anything happens
        if who == "fairrun":
            fr = FairRun(aw)
            fr.book = book
            for e in employers:
                fr.fraud.remember(e)
            run = fr.run_employer
        else:
            run = TypicalAgent(aw).run_employer
        moved = 0
        if spec.get("move") and min(to_minor(spec["move"][2]), aw.balances[spec["move"][0]].get("USD", 0)) > 0:
            src, dst, major = spec["move"]
            amount = moved = min(to_minor(major), aw.balances[src].get("USD", 0))
            aw.balances[src]["USD"] -= amount
            aw.balances[dst]["USD"] = aw.balances[dst].get("USD", 0) + amount
            held = {a: aw.get_balances(a) for a in by_id}
            if who == "fairrun":
                ok, breaches = check_segregation(book.owed, held)
                out["move"] = {"amount": amount, "caught": not ok, "detail": "; ".join(
                    f"{names[b.split(':')[0]]} is short by "
                    f"{(book.owed[b.split(':')[0]][b.split(':')[1]] - held[b.split(':')[0]].get(b.split(':')[1], 0)) / 100:,.2f} "
                    f"{b.split(':')[1]}" for b in breaches) or "every employer's own account covers what it is owed"}
            else:
                ok = pooled_check(book.owed, held)
                out["move"] = {"amount": amount, "caught": not ok,
                               "detail": "total held still equals total owed: 'all fine'"
                               if ok else "total is short"}
        attackers = ()
        if spec.get("pirate"):
            cid = spec["pirate"]
            emp.contractors = [dataclasses.replace(c, bank_account="GB-77-11-22-99887766")
                               if c.contractor_id == cid else c for c in emp.contractors]
            ref.unapproved.add((emp.employer_id, cid))
            attackers = (cid,)
        runs = 2 if spec.get("replay") else 1
        for i in range(runs):
            aw.fail_next_timeout_after_accept = bool(spec.get("timeout")) and i == 0
            res = ref.payday(run, emp, "P1")
            aw.fail_next_timeout_after_accept = False
            if who == "fairrun":
                out["status"] = res.status if i == 0 else out["status"] + f", replay: {res.status}"
                out["lines"] += [("Replay: " if i else "") + x for x in res.explanation]
                if res.held:
                    out["lines"].append("HELD, not paid: " + "; ".join(f"{k}: {v}" for k, v in res.held.items()))
            else:
                out["status"] = res["status"] if i == 0 else out["status"] + f", replay: {res['status']}"
                out["lines"] += res["notes"]
                out["issues"] += describe_typical(res, emp, names, replay=i == 1, attackers=attackers)
        out["stats"] = dict(ref.stats)
        out["balances"] = {a: aw.get_balances(a) for a in by_id}
        out["spent_moved"] = 0                              # did this payday spend money secretly moved in?
        if moved and spec["move"][1] == emp.employer_id:
            out["spent_moved"] = max(0, moved - out["balances"][emp.employer_id].get("USD", 0))
            if out["spent_moved"]:
                out["issues"].append(f"Spent {out['spent_moved'] / 100:,.2f} USD that had been secretly moved in "
                                     f"from {names[spec['move'][0]]}.")
        result[who] = out
    return result


# ---------------------------------------------------------------------------
# The referee: measures what really happened, from the Airwallex records
# ---------------------------------------------------------------------------
class Referee:
    def __init__(self, aw: WatchedMock, employers: list[Employer]):
        self.aw, self.employers = aw, employers
        self.stats: Counter = Counter()
        self.seen: Counter = Counter()                     # (account, contractor, period) -> times paid
        self.unapproved: set[tuple[str, str]] = set()      # bank details changed by an attacker

    def payday(self, run, employer: Employer, period: str):
        acct = employer.employer_id
        before = {e.employer_id: self.aw.get_balances(e.employer_id) for e in self.employers
                  if e.employer_id != acct}
        n0 = len(self.aw.payments)
        result = run(employer, period, self.employers)
        self.stats["paydays"] += 1
        for pay in self.aw.payments[n0:]:
            key = (pay["account"], pay["contractor"], period)
            self.seen[key] += 1
            usd = fx(pay["amount"], pay["currency"], "USD")
            if self.seen[key] > 1:
                self.stats["double_payments"] += 1
                self.stats["double_usd"] += usd
            elif (pay["account"], pay["contractor"]) in self.unapproved:
                self.stats["paid_to_attacker"] += 1
                self.stats["attacker_usd"] += usd
            else:
                self.stats["correct_payments"] += 1
        raided = 0
        for e in self.employers:
            if e.employer_id == acct:
                continue
            now = self.aw.get_balances(e.employer_id)
            for cur, was in before[e.employer_id].items():
                if now.get(cur, 0) < was:
                    raided += fx(was - now.get(cur, 0), cur, "USD")
        if raided:
            self.stats["paydays_using_others_money"] += 1
            self.stats["others_money_usd"] += raided
        return result


# ---------------------------------------------------------------------------
# Random worlds
# ---------------------------------------------------------------------------
_BASE = [
    ("acct_alpha", "Alpha Studio", "USD", [("alpha-anna", "EUR", 2400, "SWIFT", "DE89370400440532013000"),
                                            ("alpha-jonas", "EUR", 1800, "SWIFT", "DE02120300000000202051"),
                                            ("alpha-mike", "USD", 3000, "LOCAL", "US-000123456789")]),
    ("acct_bright", "Bright Bakery", "GBP", [("bright-tom", "GBP", 900, "LOCAL", "GB-40-47-84-70872490"),
                                             ("bright-sara", "GBP", 600, "LOCAL", "GB-20-00-00-55779911")]),
    ("acct_cedar", "Cedar Labs", "USD", [("cedar-lee", "USD", 4200, "LOCAL", "US-000987654321"),
                                          ("cedar-ria", "USD", 3900, "LOCAL", "US-000555000111")]),
]


def random_case(rng: random.Random) -> dict:
    """A random payday: random pay amounts and wallet balances, plus random trouble."""
    ids = [b[0] for b in _BASE]
    case = {"scale": {c[0]: rng.uniform(0.5, 1.5) for b in _BASE for c in b[3]},
            "funding": {a: rng.uniform(0.35, 1.9) for a in ids},
            "order": rng.sample(ids, 3),
            "timeout": rng.choice(ids) if rng.random() < 0.35 else None,
            "replay": rng.choice(ids) if rng.random() < 0.30 else None,
            "pirate": None, "move": None}
    if rng.random() < 0.30:
        a = rng.choice(_BASE)
        case["pirate"] = (a[0], rng.choice(a[3])[0])
    if rng.random() < 0.30:
        src, dst = rng.sample(["acct_alpha", "acct_cedar"], 2)        # both hold USD
        case["move"] = (src, dst, rng.uniform(0.1, 0.6))
    return case


def build_case(case: dict) -> tuple[WatchedMock, list[Employer]]:
    aw = WatchedMock()
    aw.open_account(PLATFORM_ACCOUNT)
    employers = []
    for acct, name, wc, people in _BASE:
        cs = [Contractor(cid, cid, cur, to_minor(round(amt * case["scale"][cid], 2)), method, bank, "XX")
              for cid, cur, amt, method, bank in people]
        e = Employer(acct, name, wc, cs)
        employers.append(e)
        aw.open_account(acct)
        aw.simulate_deposit(acct, wc, int(price_plan(e, "x").wallet_cost * case["funding"][acct]))
    return aw, employers


def play(case: dict, who: str) -> dict:
    """Run one random case through one agent. Returns the referee's numbers plus the agent's own outcomes."""
    aw, employers = build_case(case)
    by_id = {e.employer_id: e for e in employers}
    ref = Referee(aw, employers)
    extra: Counter = Counter()
    if who == "fairrun":
        fr = FairRun(aw)
        fr.book = FundsBook.snapshot(aw, [e.employer_id for e in employers])   # records as of funding
        for e in employers:
            fr.fraud.remember(e)                           # bank details on file before the attack
        run = fr.run_employer
    else:
        run = TypicalAgent(aw).run_employer
    if case["move"]:                                       # checked on the freshly funded wallets, then undone
        src, dst, frac = case["move"]
        book = FundsBook.snapshot(aw, [e.employer_id for e in employers])      # the books before the move
        amount = max(1, int(aw.balances[src].get("USD", 0) * frac))
        aw.balances[src]["USD"] -= amount
        aw.balances[dst]["USD"] = aw.balances[dst].get("USD", 0) + amount
        held = {e.employer_id: aw.get_balances(e.employer_id) for e in employers}
        ref.stats["secret_moves"] += 1
        if who == "fairrun":
            ok, breaches = check_segregation(book.owed, held)                  # rule R5, per employer
            caught = (not ok) and any(b.startswith(src) for b in breaches)
        else:
            caught = not pooled_check(book.owed, held)                         # total-only check
        ref.stats["secret_moves_missed"] += not caught
        aw.balances[src]["USD"] += amount
        aw.balances[dst]["USD"] -= amount
    if case["pirate"]:
        acct, cid = case["pirate"]
        e = by_id[acct]
        e.contractors = [dataclasses.replace(c, bank_account="GB-77-11-22-99887766") if c.contractor_id == cid
                         else c for c in e.contractors]
        ref.unapproved.add((acct, cid))
    for acct in case["order"]:
        aw.fail_next_timeout_after_accept = case["timeout"] == acct
        res = ref.payday(run, by_id[acct], "P1")
        aw.fail_next_timeout_after_accept = False
        if who == "fairrun":
            extra[res.status] += 1
            extra["held"] += len(res.held)
            extra["unreconciled"] += res.reconciled is False
    if case["replay"]:
        res = ref.payday(run, by_id[case["replay"]], "P1")
        if who == "fairrun":
            extra["replays_blocked"] += res.status == "BLOCKED"
    return {**ref.stats, **{f"fr_{k}": v for k, v in extra.items()}}


METRICS = [("double_payments", "Workers paid twice (timeouts and replays)"),
           ("paydays_using_others_money", "Paydays that used another employer's money"),
           ("paid_to_attacker", "Payments sent to an attacker's bank account"),
           ("secret_moves_missed", "Secret money moves not noticed")]


def stress_test(n: int = 200, seed: int = 2026) -> dict:
    """The same n random paydays through both agents. Offline rules only: no Claude calls."""
    rng = random.Random(seed)
    cases = [random_case(rng) for _ in range(n)]
    totals = {"typical": Counter(), "fairrun": Counter()}
    old, agent_module.FORCE_OFFLINE = agent_module.FORCE_OFFLINE, True
    try:
        for case in cases:
            for who in totals:
                totals[who].update(play(case, who))
    finally:
        agent_module.FORCE_OFFLINE = old
    return {"cases": n, "seed": seed, "typical": dict(totals["typical"]), "fairrun": dict(totals["fairrun"]),
            "trouble": {"timeouts": sum(c["timeout"] is not None for c in cases),
                        "replays": sum(c["replay"] is not None for c in cases),
                        "bank_changes": sum(c["pirate"] is not None for c in cases),
                        "secret_moves": sum(c["move"] is not None for c in cases)}}
