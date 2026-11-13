"""FairRun payroll engine: plan -> fraud check -> verify -> (fair split) -> pay safely -> fee -> reconcile.

Each employer runs on its own: one employer's shortfall or failure never blocks another.
Amounts, limits and duplicate protection live here in code. The Claude agents read messages,
review plans and explain; they never bypass `verify`, and the reviewer can only block, never approve past Z3.
"""
from __future__ import annotations

import threading
import time
import unicodedata
from dataclasses import dataclass, field

from .agent import PlannerAgent, ReviewerAgent
from .approvals import ROLE_TEXT, ApprovalQuorum, only_bank_change
from .airwallex_mock import AirwallexError, AmbiguousTimeout
from .fair_split import fair_split
from .fraud import FraudChecks
from .ledger import Ledger
from .models import Employer, Plan, to_major
from .pricing import price_plan, wallet_cost_of
from .verifier import verify

PLATFORM_ACCOUNT = "platform"


def norm_period(period: str) -> str:
    """'2026-w45', ' 2026-W45 ' and look-alike spellings are the SAME pay period, so a replay under a
    re-spelled period name is still a replay."""
    folded = unicodedata.normalize("NFKC", str(period)).upper()
    return "".join(ch for ch in folded if ch.isalnum() or ch in "-_/.:")


@dataclass
class RunResult:
    employer: str
    status: str                   # PAID_FULL | PAID_PARTIAL | BLOCKED | NOTHING_TO_PAY
    plan: Plan | None = None
    paid: dict[str, int] = field(default_factory=dict)
    held: dict[str, str] = field(default_factory=dict)
    escalated: str = ""
    explanation: list[str] = field(default_factory=list)
    reconciled: bool | None = None
    approvals: dict[str, dict] = field(default_factory=dict)   # contractor -> 2-of-3 status
    z3_ms: float = 0.0                                          # time spent in Z3 checks
    quarantined: int = 0                                        # unexplained money in the wallet, not spent


class FairRun:
    def __init__(self, client, ledger: Ledger | None = None):
        self.client = client
        self.ledger = ledger or Ledger()
        self.fraud = FraudChecks()
        self.planner = PlannerAgent()
        self.reviewer = ReviewerAgent()
        self.quorum = ApprovalQuorum()            # 2-of-3 approval for bank-detail changes
        self.book = None                          # optional FundsBook: what FairRun's records say each employer has
        self._lock = threading.RLock()            # one payroll run at a time: no check-then-pay race
        self._own: dict[str, int] = {}            # what the current run itself moved, per currency

    # ------------------------------------------------------------------
    def run_employer(self, employer: Employer, period: str, all_employers: list[Employer],
                     approved_holds: set[str] | None = None,
                     messages: dict[str, str] | None = None) -> RunResult:
        """Run one employer's payroll. If a FundsBook is attached, it is kept in step with what this run
        really moved, so the books change only through FairRun's own, recorded actions."""
        acct = employer.employer_id
        period = norm_period(period)
        with self._lock:
            before = self.client.get_balances(acct)
            self._own = {}
            try:
                return self._run_employer(employer, period, all_employers, approved_holds, messages)
            finally:
                if self.book is not None:
                    after = self.client.get_balances(acct)
                    for cur in set(before) | set(after) | set(self._own):
                        real = after.get(cur, 0) - before.get(cur, 0)
                        own = self._own.get(cur, 0)
                        # The books move only by what this run itself did. Money that arrived from
                        # somewhere else DURING the run is not booked, so the next run quarantines it.
                        booked = min(real, own)
                        if booked:
                            self.book.credit(acct, cur, booked)
                        if real != own:
                            self.ledger.log("books_mismatch", acct, currency=cur, own_actions=own, real_change=real)

    def _moved(self, currency: str, amount: int) -> None:
        self._own[currency] = self._own.get(currency, 0) + amount

    def _run_employer(self, employer: Employer, period: str, all_employers: list[Employer],
                      approved_holds: set[str] | None = None,
                      messages: dict[str, str] | None = None) -> RunResult:
        acct = employer.employer_id
        res = RunResult(employer=employer.name, status="")
        say = res.explanation.append

        start = self.client.get_balances(acct)
        balance = start.get(employer.wallet_currency, 0)
        say(f"{employer.name}: wallet holds {to_major(balance)} {employer.wallet_currency} "
            f"(only this wallet is considered).")
        if self.book is not None:
            wc = employer.wallet_currency
            booked = self.book.owed.get(acct, {}).get(wc, 0)
            if balance > booked:
                # Money FairRun has no record of (not a recorded deposit, not its own action). It may belong
                # to another employer, so it is never spent until it is explained.
                res.quarantined = balance - booked
                say(f"QUARANTINED {to_major(res.quarantined)} {wc}: the wallet holds more than FairRun's records "
                    f"explain ({to_major(booked)} {wc}). Unexplained money is not spent until a human explains it.")
                self.ledger.log("quarantine", acct, amount=res.quarantined, currency=wc, booked=booked)
                res.escalated = (f"{to_major(res.quarantined)} {wc} of unexplained money in {employer.name}'s wallet "
                                 f"is quarantined until explained.")
                balance = booked
            elif balance < booked:
                say(f"WARNING: the wallet holds {to_major(booked - balance)} {wc} less than FairRun's records show. "
                    f"Only what is really there is used; the gap is escalated.")
                self.ledger.log("shortfall_vs_books", acct, amount=booked - balance, currency=wc)
                res.escalated = (f"{employer.name}'s wallet holds {to_major(booked - balance)} {wc} less than "
                                 f"FairRun's records show.")

        # 1. Fraud checks -> hold suspicious payouts, keep the rest moving.
        holds = self.fraud.check(employer, all_employers)
        names = {c.contractor_id: c.name for c in employer.contractors}
        for cid, text in (messages or {}).items():
            read = self.planner.read_request(text, names.get(cid, cid))
            self.ledger.log("message", acct, contractor=cid, message_kind=read["kind"],
                            red_flags=read["red_flags"], source=read["source"])
            say(f"Message from {cid} read by agent ({read['source']}): {read['kind']}, "
                f"red flags: {', '.join(read['red_flags']) or 'none'}.")
            if read["recommended_action"] == "hold_for_out_of_band_check":
                prev = holds.get(cid)
                holds[cid] = (prev + "; " if prev else "") + "message asks to change bank details"
        accounts = {c.contractor_id: c.bank_account for c in employer.contractors}
        for cid in list(holds):
            if approved_holds and cid in approved_holds:
                say(f"Hold on {cid} released: human approved after out-of-band check.")
                holds.pop(cid)
                continue
            if self.quorum is not None and only_bank_change(holds[cid]):
                req = self.quorum.open(acct, cid, accounts[cid])
                q = self.quorum.status(acct, cid, accounts[cid])
                res.approvals[cid] = q
                if q["released"]:
                    who = " + ".join(ROLE_TEXT[r] for r in q["valid"])
                    say(f"Hold on {cid} released: {len(q['valid'])} of 3 independent approvals verified ({who}).")
                    self.ledger.log("release", acct, contractor=cid, request=req["id"], approvals=q["valid"])
                    holds.pop(cid)
                else:
                    say(f"{cid}: new bank details need 2 of 3 independent approvals; {q['why']}.")
        for cid, why in holds.items():
            say(f"HOLD {cid}: {why}.")
            self.ledger.log("hold", acct, contractor=cid, reason=why)
        res.held = holds
        payable = {c.contractor_id: c.amount for c in employer.contractors if c.contractor_id not in holds}

        # 2. Price the full plan and verify it.
        try:
            plan = price_plan(employer, period, payable)
        except KeyError as e:
            res.status = "BLOCKED"
            say(f"BLOCKED: unsupported currency or route {e.args[0]!r}. Nothing was paid.")
            self.ledger.log("blocked", acct, reason=f"unsupported currency or route {e.args[0]!r}")
            return res
        if not plan.payouts:
            res.status = "NOTHING_TO_PAY"
            return res
        t0 = time.perf_counter()
        verdict = verify(plan, balance, self.ledger.executed_batches(),
                         self.ledger.live_contractors(acct, period))
        res.z3_ms += (time.perf_counter() - t0) * 1000
        self.ledger.log("verify", acct, batch=plan.batch_key, ok=verdict.ok,
                        broken=verdict.broken_rules, detail=verdict.detail)

        if not verdict.ok and {"R3_not_replayed", "R4_one_per_contractor"} & set(verdict.broken_rules):
            res.status = "BLOCKED"
            say("BLOCKED by Z3 check: " + "; ".join(verdict.detail))
            return res

        # 3. Shortfall -> fair partial split from this employer's own money only.
        if not verdict.ok and "R2_within_balance" in verdict.broken_rules:
            say("Z3 check failed R2_within_balance: " + "; ".join(verdict.detail))
            say("Other employers' balances are NOT used. Computing a fair partial run.")
            short_employer = Employer(acct, employer.name, employer.wallet_currency,
                                      [c for c in employer.contractors if c.contractor_id in payable])
            split, share = fair_split(short_employer, balance)
            plan = price_plan(employer, period, split, note=f"partial run, {share / 10:.1f}% each")
            t0 = time.perf_counter()
            verdict = verify(plan, balance, self.ledger.executed_batches(),
                             self.ledger.live_contractors(acct, period))
            res.z3_ms += (time.perf_counter() - t0) * 1000
            self.ledger.log("verify", acct, batch=plan.batch_key, ok=verdict.ok,
                            broken=verdict.broken_rules, note=plan.note)
            if not verdict.ok:
                res.status = "BLOCKED"
                say("Partial plan still fails: " + "; ".join(verdict.detail))
                return res
            owed = sum(c.amount for c in short_employer.contractors)
            given = sum(p.amount for p in plan.payouts)
            res.escalated = ((res.escalated + " ") if res.escalated else "") + (
                             f"{employer.name} could pay {share / 10:.1f}% of each contractor. "
                             f"Remaining {to_major(owed - given)} {employer.contractors[0].currency if len({c.currency for c in employer.contractors}) == 1 else '(mixed currencies)'} needs a top-up "
                             f"or a human decision.")
            say("ESCALATED: " + res.escalated)
            self.ledger.log("escalate", acct, message=res.escalated)
            res.status = "PAID_PARTIAL"
        else:
            say(f"Z3 check passed: own funds only, within balance, new batch, one payout per contractor.")
            res.status = "PAID_FULL"

        res.plan = plan

        # Reviewer agent: read-only second check. It can only make FairRun stricter.
        summary = self._review_summary(employer, plan, balance, res.status)
        review = self.reviewer.review(employer.name, summary, res.explanation)
        self.ledger.log("review", acct, batch=plan.batch_key, **review)
        if review["verdict"] != "APPROVE":
            res.status = "BLOCKED"
            say(f"Reviewer agent REJECTED the batch ({review['source']}): {review['reason']}")
            return res
        say(f"Reviewer agent approved ({review['source']}): {review['reason']}")

        # 4. Execute: FX first (one conversion per currency), then payouts, then platform fee.
        actual_cost = plan.wallet_cost
        for cur, need in plan.conversions.items():
            if cur != employer.wallet_currency:
                rid = self.ledger.new_intent(acct, f"fx:{cur}", period, plan.batch_key, cur, need)
                sold = self.client.convert(acct, rid, employer.wallet_currency, cur, need)
                self.ledger.set_state(rid, "PAID", sold=sold, sold_currency=employer.wallet_currency)
                self._moved(employer.wallet_currency, -sold)
                self._moved(cur, need)
                planned = wallet_cost_of({cur: need}, employer.wallet_currency)
                actual_cost += sold - planned
                say(f"Converted {to_major(sold)} {employer.wallet_currency} -> {to_major(need)} {cur} "
                    f"(includes SWIFT fees; plan estimated {to_major(planned)}).")
        if actual_cost != plan.wallet_cost:
            # Re-run the balance rule with the REAL FX cost before any contractor is paid.
            if actual_cost > balance:
                res.status = "BLOCKED"
                say(f"Re-check FAILED with the real FX cost: needs {to_major(actual_cost)} but wallet held "
                    f"{to_major(balance)}. No contractor paid; converted funds stay in this employer's wallet.")
                self.ledger.log("recheck", acct, ok=False, actual_cost=actual_cost, balance=balance)
                return res
            say(f"Re-checked with the real FX cost {to_major(actual_cost)} {employer.wallet_currency}: "
                f"still within this wallet's {to_major(balance)}.")
            self.ledger.log("recheck", acct, ok=True, actual_cost=actual_cost, balance=balance)

        for p in plan.payouts:
            rid = self.ledger.new_intent(acct, p.contractor_id, period, plan.batch_key, p.currency, p.amount)
            transfer = self._pay_safely(acct, rid, p.currency, p.amount, p.fee, say, p.contractor_id, p.method)
            if transfer is not None:
                res.paid[p.contractor_id] = p.amount

        fee_rid = self.ledger.new_intent(acct, "platform_fee", period, plan.batch_key,
                                         employer.wallet_currency, plan.platform_fee)
        self.client.create_charge(acct, PLATFORM_ACCOUNT, fee_rid, employer.wallet_currency, plan.platform_fee)
        self.ledger.set_state(fee_rid, "PAID")
        self._moved(employer.wallet_currency, -plan.platform_fee)
        self.ledger.mark_batch(plan.batch_key, acct)
        self.fraud.remember(employer, skip=set(res.held))

        # 5. Reconcile this employer only.
        end = self.client.get_balances(acct)
        spent = start.get(employer.wallet_currency, 0) - end.get(employer.wallet_currency, 0)
        res.reconciled = spent <= actual_cost
        say(f"Reconciled: spent {to_major(spent)} {employer.wallet_currency} "
            f"(allowed {to_major(actual_cost)}): {'OK' if res.reconciled else 'MISMATCH'}.")
        for c in plan.conversions:
            if c != employer.wallet_currency:
                delta = end.get(c, 0) - start.get(c, 0)
                note = "fully used" if delta == 0 else (
                    f"{to_major(abs(delta))} {c} {'left over' if delta > 0 else 'short'} - "
                    "the provider charged SWIFT fees differently from the plan")
                say(f"  {c}: {to_major(start.get(c, 0))} -> {to_major(end.get(c, 0))} ({note}).")
        self.ledger.log("reconcile", acct, spent=spent, plan_cost=plan.wallet_cost,
                        actual_cost=actual_cost, ok=res.reconciled)
        return res

    # ------------------------------------------------------------------
    @staticmethod
    def _review_summary(employer: Employer, plan: Plan, balance: int, status: str) -> dict:
        """Everything the reviewer needs to re-add the numbers itself, in major units."""
        wc = employer.wallet_currency
        payouts_by_cur: dict[str, int] = {}
        fees_by_cur: dict[str, int] = {}
        for p in plan.payouts:
            payouts_by_cur[p.currency] = payouts_by_cur.get(p.currency, 0) + p.amount
            fees_by_cur[p.currency] = fees_by_cur.get(p.currency, 0) + p.fee
        lines = []
        for cur, need in plan.conversions.items():
            in_wallet = wallet_cost_of({cur: need}, wc)
            how = "paid directly" if cur == wc else f"converted from {to_major(in_wallet)} {wc}"
            lines.append(f"{to_major(payouts_by_cur.get(cur, 0))} {cur} payouts + "
                         f"{to_major(fees_by_cur.get(cur, 0))} {cur} SWIFT fees = {to_major(need)} {cur}, "
                         f"{how}")
        lines.append(f"+ FairRun platform fee {to_major(plan.platform_fee)} {wc}")
        lines.append(f"= total wallet cost {to_major(plan.wallet_cost)} {wc} "
                     f"(wallet balance {to_major(balance)} {wc})")
        return {
            "employer_wallet": employer.employer_id,
            "wallet_currency": wc,
            "run_type": ("PARTIAL: employer is short; a fair partial run is paid and the rest is "
                         "escalated to a human (this is the intended handling)"
                         if status == "PAID_PARTIAL" else "FULL"),
            "payouts": [{"contractor": p.contractor_id, "paid_from_wallet": p.source_account,
                         "amount": f"{to_major(p.amount)} {p.currency}",
                         "swift_fee": f"{to_major(p.fee)} {p.currency}"} for p in plan.payouts],
            "cost_breakdown": lines,
        }

    def _pay_safely(self, acct, rid, currency, amount, fee, say, contractor, method="LOCAL"):
        """Never pay without knowing what already happened."""
        try:
            t = self.client.create_transfer(acct, rid, currency, amount, fee,
                                            contractor_id=contractor, method=method)
        except AmbiguousTimeout:
            self.ledger.set_state(rid, "UNKNOWN")
            say(f"Timeout paying {contractor}: outcome unknown. Looking it up before any retry...")
            t = self.client.find_transfer_by_request_id(acct, rid)
            if t is not None:
                say(f"Found {t.transfer_id} already accepted ({t.status}). NOT paying again.")
            else:
                say("Not found: retrying with the SAME request_id.")
                t = self.client.create_transfer(acct, rid, currency, amount, fee,
                                                contractor_id=contractor, method=method)
        except AirwallexError as e:
            self.ledger.set_state(rid, "REJECTED", code=e.code)
            say(f"Payout to {contractor} rejected by Airwallex: {e.code}.")
            return None
        # Sandbox: transfers on behalf of a connected account stay PROCESSING until simulated.
        if hasattr(self.client, "simulate_transition"):
            self.client.simulate_transition(t.transfer_id, "SENT", account=acct)
            self.client.simulate_transition(t.transfer_id, "PAID", account=acct)
        self.ledger.set_state(rid, "PAID", transfer_id=t.transfer_id)
        self._moved(currency, -(amount + fee))
        say(f"Paid {contractor}: {to_major(amount)} {currency}"
            + (f" (+{to_major(fee)} SWIFT fee)" if fee else "") + ".")
        return t
