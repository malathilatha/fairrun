"""Claude agents for FairRun.

PlannerAgent  - reads contractor messages (e.g. bank-change requests) and explains each run in plain English.
ReviewerAgent - reviews a verified plan and returns APPROVE or REJECT with a reason. It has no tools and
                cannot pay; it can only make FairRun STRICTER (a REJECT holds the batch), never looser.

Both agents work without an API key: they fall back to deterministic rules, so tests and offline demos run.
The model never decides amounts or limits - those stay in code and in the Z3 check.
"""
from __future__ import annotations

import json
import os
import re

PLANNER_MODEL = os.environ.get("FAIRRUN_PLANNER_MODEL", "claude-sonnet-5-5")
REVIEWER_MODEL = os.environ.get("FAIRRUN_REVIEWER_MODEL", "claude-haiku-5-5")


FORCE_OFFLINE = False        # set True to use the built-in rules only (stress tests, public demo)

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_ACCOUNT = re.compile(r"\b(?:[A-Z]{2}-)?\d[\d-]{6,}\d\b")


def mask_pii(text: str) -> str:
    """Hide bank account numbers before any text leaves for the model: keep only the last 4 characters."""
    def hide(m):
        raw = m.group(0)
        return f"[account ending {raw[-4:]}]"
    return _ACCOUNT.sub(hide, _IBAN.sub(hide, text))


def _client():
    if FORCE_OFFLINE or not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic
        return anthropic.Anthropic()
    except Exception as e:
        _debug(f"cannot create Claude client, using rules: {e}")
        return None


def _debug(msg: str) -> None:
    if os.environ.get("FAIRRUN_DEBUG"):
        print(f"[agent] {msg}")


def _parse_json(text: str) -> dict | None:
    """Accept JSON even if wrapped in ```json fences or followed by extra text."""
    text = re.sub(r"```(?:json)?", "", text)
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start):
        depth += ch == "{"
        depth -= ch == "}"
        if depth == 0:
            try:
                return json.loads(text[start:i + 1])
            except json.JSONDecodeError:
                return None
    return None


def _ask_json(model: str, system: str, user: str, max_tokens: int = 600) -> dict | None:
    client = _client()
    if client is None:
        return None
    try:
        msg = client.messages.create(model=model, max_tokens=max_tokens, system=system,
                                     messages=[{"role": "user", "content": mask_pii(user)}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    except Exception as e:
        _debug(f"Claude call failed ({model}), using rules: {type(e).__name__}: {str(e)[:200]}")
        return None   # any API problem -> safe fallback, never an unsafe default
    out = _parse_json(text)
    if out is None:
        _debug(f"could not read JSON from {model} (stop_reason={getattr(msg, 'stop_reason', '?')}), "
               f"using rules. Raw reply: {text[:300]!r}")
    return out


# ---------------------------------------------------------------------------
_URGENT = re.compile(r"\b(urgent|asap|today|immediately|right now)\b", re.I)
_BANK = re.compile(r"\b(new (bank|account)|changed? (my )?bank|bank details|iban|account number|sort code)\b", re.I)


class PlannerAgent:
    def read_request(self, text: str, claimed_sender: str) -> dict:
        """Classify an inbound contractor message. Returns kind, red_flags, recommended_action."""
        system = ("You review messages sent to a payroll platform. Return ONLY JSON: "
                  '{"kind": "bank_change"|"payment_query"|"other", "red_flags": [short strings], '
                  '"recommended_action": "hold_for_out_of_band_check"|"no_action"}. '
                  "Any request to change bank details must be held for an out-of-band check, "
                  "however legitimate it looks. Never suggest paying.")
        out = _ask_json(PLANNER_MODEL, system, f"Claimed sender: {claimed_sender}\nMessage:\n{text}")
        if out and out.get("kind") in {"bank_change", "payment_query", "other"}:
            out.setdefault("red_flags", [])
            if out["kind"] == "bank_change":          # code enforces the rule, whatever the model said
                out["recommended_action"] = "hold_for_out_of_band_check"
            out["source"] = "claude"
            return out
        flags = []
        if _BANK.search(text):
            flags.append("asks to change bank details")
        if _URGENT.search(text):
            flags.append("urgency pressure")
        kind = "bank_change" if _BANK.search(text) else "other"
        return {"kind": kind, "red_flags": flags, "source": "rules",
                "recommended_action": "hold_for_out_of_band_check" if kind == "bank_change" else "no_action"}

    def explain(self, employer_name: str, facts: list[str]) -> str:
        """Plain-English summary of a run, built ONLY from the engine's facts."""
        system = ("Summarise a payroll run for the platform operator in 3-4 short sentences. "
                  "Use only the facts given; do not invent amounts. Say clearly if another employer's "
                  'money was used (it never should be). Return ONLY JSON: {"summary": "..."}')
        out = _ask_json(PLANNER_MODEL, system, f"Employer: {employer_name}\nFacts:\n- " + "\n- ".join(facts))
        if out and isinstance(out.get("summary"), str):
            return out["summary"]
        key = [f for f in facts if f.startswith(("ESCALATED", "BLOCKED", "HOLD", "Z3 check"))]
        return f"{employer_name}: " + " ".join(key or facts[-1:])


class ReviewerAgent:
    """Second pair of eyes. Read-only: it sees the plan and facts, returns a verdict, cannot act."""

    def review(self, employer_name: str, plan_summary: dict, facts: list[str]) -> dict:
        system = ("You are a payroll reviewer with NO ability to send money. Check the batch yourself:\n"
                  "1. every payout's paid_from_wallet equals employer_wallet;\n"
                  "2. the cost_breakdown adds up (payouts + SWIFT fees, converted where shown, + platform fee "
                  "= total wallet cost) and the total is within the wallet balance;\n"
                  "3. nothing in the facts is suspicious and unhandled. Payouts that are on HOLD are already "
                  "excluded, so a hold is handled.\n"
                  "A PARTIAL run with the shortfall escalated to a human is the intended, correct handling; "
                  "do not reject it for that reason alone. Reject only for a real inconsistency.\n"
                  "Return ONLY JSON: "
                  '{"verdict": "APPROVE"|"REJECT", "reason": "one sentence, under 25 words"}. '
                  "No other text.")
        user = f"Employer: {employer_name}\nPlan: {json.dumps(plan_summary)}\nFacts:\n- " + "\n- ".join(facts)
        out = _ask_json(REVIEWER_MODEL, system, user)
        verdict = str((out or {}).get("verdict", "")).strip().upper()
        if verdict in {"APPROVE", "REJECT"}:
            return {"verdict": verdict, "reason": str(out.get("reason", "")), "source": "claude"}
        if out is not None:
            _debug(f"reviewer returned an unexpected verdict {out.get('verdict')!r}, using rules")
        # Offline rule: reject if any payout leaves from another wallet, otherwise approve.
        foreign = [p for p in plan_summary.get("payouts", [])
                   if p.get("paid_from_wallet", p.get("source")) != plan_summary.get("employer_wallet",
                                                                                    plan_summary.get("employer"))]
        if foreign:
            return {"verdict": "REJECT", "reason": "payout from a wallet that is not this employer's",
                    "source": "rules"}
        return {"verdict": "APPROVE", "reason": "plan is consistent with this employer's own wallet",
                "source": "rules"}
