"""FairRun dashboard: the whole story in seven clicks, each replaying a real incident.

Run (from the project folder):   streamlit run dashboard/app.py
Runs on the built-in Airwallex mock, so it works offline and every click is repeatable.
The same engine runs on the real Airwallex sandbox with:  python -m scenarios.real_run
"""
from __future__ import annotations

import dataclasses
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit as st

from fairrun.approvals import ROLE_TEXT, ROLES
from fairrun.attacks import (edit_audit_log, foreign_wallet, hide_money, payroll_pirate, quantum_attacker,
                             spend_moved_money)
from fairrun.baseline import METRICS, Referee, TypicalAgent, clone_world, describe_typical, run_custom, stress_test
from fairrun.engine import FairRun
from fairrun.fraud import FraudChecks
from fairrun.models import to_major, to_minor
from fairrun.pricing import price_plan
from fairrun.quantum_demo import ALGORITHMS
from fairrun.quantum_demo import run_all as run_qday
from fairrun.solvency import FundsBook, prove_lemmas
from fairrun.verifier import RULES, prove_no_borrowing, smallest_fix
from fairrun.zk_solvency import ZkSolvencyProver, verify_zk_inclusion
from scenarios.demo_run import build_world

st.set_page_config(page_title="FairRun", page_icon="🛡️", layout="wide")


def show_table(rows):
    """Plain markdown table. st.table needs pyarrow, which some locked-down Windows PCs block."""
    if not rows:
        return
    cols = list(rows[0])
    cell = lambda v: str(v).replace("|", "\\|").replace("\n", " ")
    lines = ["| " + " | ".join(cell(c) for c in cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(cell(r.get(c, "")) for c in cols) + " |" for r in rows]
    st.markdown("\n".join(lines))

PERIOD = "2026-W45"
RULE_TEXT = {
    "R1_own_funds": "Only this employer's own money",
    "R2_within_balance": "Within this employer's balance",
    "R3_not_replayed": "Not a repeated batch",
    "R4_one_per_contractor": "One payout per contractor",
}

# Real incidents each situation replays: (headline, source label, url, what a system without these checks does)
INCIDENTS = {
    1: ("89% of payroll and finance staff hit payment issues in the past year; manual error is the top cause (48%).",
        "Finity UK Payroll Efficiency Report, Apr 2026",
        "https://onrec.com/news/news-archive/9-in-10-payroll-professionals-experience-errors-finity-research-uncovers-near",
        "A timeout looks like a failure, the retry is sent, and the contractor is paid twice."),
    2: ("UK unpaid-wage claims reached £57M in 2025/26, an eight-year high, as employers ran out of money.",
        "HRreview, May 2026",
        "https://www.pulse.bot/human-resources/news/unpaid-wage-claims-hit-eight-year-high-as-business-failures-rise-bad8ea85-5b36-44c9-90eb-46dac3531bd8/",
        "An agent adds up all wallets, sees 'plenty of money', and pays Bright's staff with other employers' money."),
    4: ("Disconnected systems are behind 30% of payroll errors; a re-sent batch is a classic one.",
        "Finity UK Payroll Efficiency Report, Apr 2026",
        "https://onrec.com/news/news-archive/9-in-10-payroll-professionals-experience-errors-finity-research-uncovers-near",
        "The same batch is paid a second time."),
    5: ("'Payroll pirates': attackers had a help desk reset a doctor's password, changed his bank details in "
        "Workday, and took his salary. Nobody noticed until payday.",
        "The Register, Feb 2026 (Binary Defense, Dec 2025 incident)",
        "https://www.theregister.com/2026/02/11/payroll_pirates_business_social_engineering/",
        "The new bank details are accepted and the pay goes to the attacker."),
    6: ("Synapse: US regulator (CFPB) sued, alleging records did not show where customers' money was; "
        "$60-90M gap. Same pattern as MyPayrollHR (2019): about $26M of payroll money diverted.",
        "PYMNTS, Aug 2025",
        "https://www.pymnts.com/legal/2025/synapse-faces-cfpb-over-fund-reconciliation-gaps/",
        "A total-only check says 'everything balances', because the grand total did not change."),
    7: ("Payroll data (bank accounts, salaries, IDs) stolen after a ransomware attack on an ADP partner "
        "serving the Middle East. Citi puts bank quantum risk at $2.0-3.3T.",
        "The Register via Slashdot, May 2025",
        "https://tech.slashdot.org/story/25/05/16/1422227/",
        "Stolen encrypted data opens once a quantum computer breaks today's classical keys."),
}


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def fresh_state() -> None:
    aw, employers = build_world()
    s = st.session_state
    s.aw, s.employers = aw, employers
    s.fr = FairRun(aw)
    s.accts = [e.employer_id for e in employers]
    s.names = {e.employer_id: e.name for e in employers}
    s.book = FundsBook.snapshot(aw, s.accts)      # FairRun's records: updated only by FairRun's own actions
    s.fr.book = s.book
    s.last = None                                 # what the last click did
    s.version = 0                                 # bumps on every change of balances
    s.proof_version = None
    s.proof = None
    s.prover = ZkSolvencyProver()
    s.proof_view = None
    s.want_proof = False
    s.moved = None                                # (amount) of a secret move, so it can be undone
    s.quantum = None
    s.attacks = {}
    s.own_result = None
    s.stress = None
    s.want_attack = None
    s.originals = [list(e.contractors) for e in employers]
    s.n = 0                                       # every click gets a fresh payroll period
    s.alpha_period = None


if "aw" not in st.session_state:
    fresh_state()
S = st.session_state


def money(bal: dict) -> str:
    return " · ".join(f"{to_major(v)} {c}" for c, v in sorted(bal.items()) if v) or "empty"


def employer(emp_id: str):
    return next(e for e in S.employers if e.employer_id == emp_id)


def run(title: str, what: str, emp_id: str, period: str = PERIOD, replay: bool = False,
        attackers: tuple = (), **kw) -> None:
    """Run one employer through the real FairRun engine and remember what it decided.
    The same situation also runs through the baseline 'typical agent', on an independent copy."""
    aw2, emps2 = clone_world(S.aw, S.employers)
    emp2 = next(e for e in emps2 if e.employer_id == emp_id)
    typ_out = Referee(aw2, emps2).payday(TypicalAgent(aw2).run_employer, emp2, period)
    typ = {"issues": describe_typical(typ_out, emp2, S.names, replay=replay, attackers=attackers),
           "notes": typ_out["notes"], "status": typ_out["status"]}
    bal0 = S.aw.get_balances(emp_id).get(employer(emp_id).wallet_currency, 0)
    start = len(S.fr.ledger.entries())
    others = {a: S.aw.get_balances(a) for a in S.accts if a != emp_id}
    t0 = time.perf_counter()
    res = S.fr.run_employer(employer(emp_id), period, S.employers, **kw)
    ms = (time.perf_counter() - t0) * 1000
    touched = sum(1 for a, b in others.items() if S.aw.get_balances(a) != b)
    new = S.fr.ledger.entries()[start:]
    first = next((b for _, k, e, b in new if k == "verify" and e == emp_id), None)
    fix = 0
    if first and "R2_within_balance" in first.get("broken", []):
        fix = smallest_fix(price_plan(employer(emp_id), period), bal0)
    S.last = {"title": title, "what": what, "emp": emp_id, "res": res, "first_check": first,
              "entries": len(new), "ms": ms, "touched": touched, "n": int(title.split(" ")[0]),
              "typ": typ, "fix": fix}
    S.book = FundsBook.snapshot(S.aw, S.accts)    # FairRun's books follow its own, reconciled actions
    S.fr.book = S.book
    S.version += 1
    S.proof, S.proof_view = None, None            # an old proof must not be shown against new balances


# ---------------------------------------------------------------------------
# The six situations
# ---------------------------------------------------------------------------
DEFAULT_WALLETS = {"acct_alpha": ("USD", 15000), "acct_bright": ("GBP", 1200), "acct_cedar": ("USD", 2000)}


def fresh_period() -> str:
    S.n += 1
    return f"{PERIOD}-{S.n}"


def clean(**balances) -> None:
    """Every situation starts from its own clean setup, so any click can be repeated in any order.
    Undoes a secret move, restores contractors' original bank details, and sets the named wallets."""
    if S.moved:
        S.aw.balances["acct_cedar"]["USD"] += S.moved
        S.aw.balances["acct_alpha"]["USD"] -= S.moved
        S.moved = None
    for e, orig in zip(S.employers, S.originals):
        e.contractors = list(orig)
    S.quantum = None
    S.fr.fraud = FraudChecks()                    # FairRun's memory of bank details: back to the originals
    for e in S.employers:
        S.fr.fraud.remember(e)
    for acct, (cur, amount) in DEFAULT_WALLETS.items():       # every wallet back to its starting money
        S.aw.balances[acct] = {cur: to_minor(amount)}
    for key, amount in balances.items():
        acct, cur = key.split("_")
        S.aw.balances["acct_" + acct][cur.upper()] = to_minor(amount)
    S.book = FundsBook.snapshot(S.aw, S.accts)
    S.fr.book = S.book                            # FairRun spends only money its records explain


def s1():
    clean(alpha_usd=15000)
    S.aw.fail_next_timeout_after_accept = True
    S.alpha_period = fresh_period()
    run("1 · Alpha pays 3 contractors, with currency conversion and a network failure",
        "Alpha pays in USD to people paid in EUR and USD. One payment times out after Airwallex accepted it.",
        "acct_alpha", period=S.alpha_period)


def s2():
    clean(bright_gbp=1200)
    run("2 · Bright Bakery cannot afford payroll",
        "Bright's wallet is short. A naive agent adds up all wallets ('plenty of money!') and approves.",
        "acct_bright", period=fresh_period())


def s3():
    clean(cedar_usd=2000, bright_gbp=1200)
    before = S.aw.get_balances("acct_bright")
    S.aw.simulate_deposit("acct_cedar", "USD", to_minor(9000))
    after = S.aw.get_balances("acct_bright")
    S.book = FundsBook.snapshot(S.aw, S.accts)    # a recorded deposit: the books know about it
    S.fr.book = S.book
    run("3 · Cedar's late deposit lands, then Cedar pays",
        f"Cedar's money arrives. Bright's wallet stays {money(before)} → {money(after)}: unchanged.",
        "acct_cedar", period=fresh_period())


def s4():
    if S.alpha_period is None:                    # nothing to replay yet: run Alpha's payroll first
        clean(alpha_usd=15000)
        S.alpha_period = fresh_period()
        S.fr.run_employer(employer("acct_alpha"), S.alpha_period, S.employers)
    clean()
    run("4 · Alpha's batch is triggered a second time",
        "The same payroll is replayed (a retry bug, or a malicious trigger).", "acct_alpha",
        period=S.alpha_period, replay=True)


def s5():
    clean(bright_gbp=2000)
    bright = employer("acct_bright")
    tom = bright.contractors[0]
    bright.contractors[0] = dataclasses.replace(tom, bank_account="US-000987654321")
    email = ("Hi, it's Tom. I changed my bank this week, please send today's pay to my new "
             "account US-000987654321. Urgent, rent is due today!")
    run("5 · Tom emails: 'urgent, pay my new bank account'",
        f"Email received: “{email}”", "acct_bright", period=fresh_period(), attackers=("bright-tom",),
        messages={"bright-tom": email})


def s6():
    clean(cedar_usd=2000)
    moved = min(S.aw.balances["acct_cedar"].get("USD", 0), 50000)
    S.aw.balances["acct_cedar"]["USD"] -= moved
    S.aw.balances["acct_alpha"]["USD"] = S.aw.balances["acct_alpha"].get("USD", 0) + moved
    S.moved = moved
    S.version += 1
    S.last = {"title": "6 · Someone secretly moves 500 USD from Cedar's account to Alpha's",
              "what": "Done outside FairRun. The grand total of money stays exactly the same.",
              "emp": None, "res": None, "first_check": None, "entries": 0, "n": 6}
    S.want_proof = True


def s7():
    clean()
    S.quantum = run_qday()
    S.last = {"title": "7 · Quantum Day: what if data stolen today is opened in the future?",
              "what": "An attacker copies encrypted data today and waits for a quantum computer. "
                      "Same stolen data, two designs: classical-only locks versus FairRun's hybrid locks.",
              "emp": None, "res": None, "first_check": None, "entries": 0, "n": 7}


def check_proofs():
    S.want_proof = True


def reset():
    fresh_state()


def atk_wallet():
    S.attacks["wallet"] = foreign_wallet(S.aw, employer("acct_bright"), employer("acct_alpha"))


def atk_log():
    res = edit_audit_log(S.fr.ledger)
    if res["caught"] is None:                     # nothing recorded yet: attack a scratch run instead
        aw2, emps2 = build_world()
        fr2 = FairRun(aw2)
        fr2.run_employer(emps2[0], "W1", emps2)
        res = edit_audit_log(fr2.ledger)
    S.attacks["log"] = res


def atk_hide():
    S.want_attack = "hide"                        # built below, with a spinner


def atk_pirate():
    S.attacks["pirate"] = payroll_pirate(*build_world())     # a fresh world: the story is never touched


def atk_launder():
    S.attacks["launder"] = spend_moved_money()


def atk_all():
    for f in (atk_wallet, atk_log, atk_hide, atk_pirate, atk_quantum, atk_launder):
        f()


def atk_quantum():
    S.attacks["quantum"] = quantum_attacker()


# ---------------------------------------------------------------------------
# Sidebar: the situations
# ---------------------------------------------------------------------------
with st.sidebar:
    st.header("Try a situation")
    st.caption("Each one replays a real incident. Each click starts from its own clean setup: any order, as often "
               "as you like.")
    cur = (S.last or {}).get("title", "")[:1]          # the situation on screen now, "" before the first click
    kind = lambda n: "primary" if cur == str(n) else "secondary"
    st.markdown("**Today's problems**")
    st.button("1 · Normal payroll with FX + network failure", on_click=s1, use_container_width=True, type=kind(1))
    st.button("2 · An employer is short of money", on_click=s2, use_container_width=True, type=kind(2))
    st.button("3 · A late deposit lands", on_click=s3, use_container_width=True, type=kind(3))
    st.button("4 · A payroll batch is replayed", on_click=s4, use_container_width=True, type=kind(4))
    st.button("5 · Urgent 'new bank account' email", on_click=s5, use_container_width=True, type=kind(5))
    st.button("6 · Secretly move 500 USD between accounts", on_click=s6, use_container_width=True, type=kind(6))
    st.markdown("**Tomorrow's risk**")
    st.button("7 · Quantum Day: data stolen today", on_click=s7, use_container_width=True, type=kind(7))
    st.divider()
    st.button("Check every employer's proof", on_click=check_proofs, use_container_width=True)
    st.button("Reset demo", on_click=reset, use_container_width=True)
    st.divider()
    st.caption("Runs on the built-in Airwallex mock. The same engine runs on the real Airwallex sandbox "
               "(`python -m scenarios.real_run`).")
    agents = "Claude agents" if os.environ.get("ANTHROPIC_API_KEY") else "built-in rules (offline)"
    st.caption(f"Fraud-reading and review agents: {agents}")

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("FairRun")
st.markdown("**A payroll agent that never mixes employer money.** One platform pays contractors for many "
            "employers. FairRun makes sure Company A's money never pays Company B's workers, and lets every "
            "company prove it.")

story, own, stress, cheat = st.tabs(["The story: 7 situations", "Your own case", "Stress test: random paydays",
                                     "Try to cheat FairRun"])

with story:
    # ---------------------------------------------------------------------------
    # Wallets
    # ---------------------------------------------------------------------------
    st.subheader("Each employer's own wallet")
    cols = st.columns(3)
    for col, emp in zip(cols, S.employers):
        bal = S.aw.get_balances(emp.employer_id)
        with col.container(border=True):
            st.markdown(f"**{emp.name}**")
            owed = sum(c.amount for c in emp.contractors)
            st.metric(f"Wallet ({emp.wallet_currency})", to_major(bal.get(emp.wallet_currency, 0)),
                      help="Live balance of this employer's own account only.")
            other = {c: v for c, v in bal.items() if c != emp.wallet_currency and v}
            if other:
                st.caption("Also holds: " + money(other))
            st.caption(f"{len(emp.contractors)} contractors · payroll {to_major(owed)} (before fees)")
    plat = S.aw.get_balances("platform")
    st.caption(f"Platform fees collected: {money(plat)}")
    st.markdown(":blue-badge[Built on Airwallex] Each wallet is an **Airwallex connected account** · every call is "
                "scoped to one employer (`x-on-behalf-of`) · currency exchange is an **Airwallex FX conversion** · "
                "payouts are **Airwallex transfers** with a `request_id` · FairRun's fee is a **platform charge**. "
                "Airwallex keeps each employer's money in its own account; FairRun proves it stays there.")

    # ---------------------------------------------------------------------------
    # What FairRun decided
    # ---------------------------------------------------------------------------
    STATUS = {"PAID_FULL": ("green", "Paid in full"), "PAID_PARTIAL": ("orange", "Paid fairly, rest escalated"),
              "BLOCKED": ("red", "Blocked, nothing paid"), "NOTHING_TO_PAY": ("gray", "Nothing to pay")}

    st.subheader("What FairRun decided")
    last = S.last
    if not last:
        st.info("Pick a situation in the sidebar. Start with **2 · An employer is short of money**.")
    else:
        st.markdown(f"### {last['title']}")
        inc = INCIDENTS.get(last.get("n"))
        if inc:
            head, src, url, without = inc
            with st.container(border=True):
                st.markdown(f"📰 **This really happened.** {head}  \n[{src}]({url})")
                if last["res"] is None:
                    st.markdown(f":red-badge[Without these checks] {without}")
        st.write(last["what"])
        res = last["res"]
        if res is not None:
            color, label = STATUS.get(res.status, ("gray", res.status))
            if res.status == "PAID_FULL" and res.held:
                color, label = "orange", "Paid, with a payout held for review"
            typ = last.get("typ")
            left, right = st.columns(2)
            with left.container(border=True):
                st.markdown("**Typical agent** (our simple baseline, run live on a copy of the same data)")
                if typ and typ["issues"]:
                    st.markdown(f"## ❌ {len(typ['issues'])} mistake{'s' if len(typ['issues']) > 1 else ''}")
                    for issue in typ["issues"]:
                        st.markdown(f"- :red[{issue}]")
                else:
                    st.markdown("## ✅ No mistake here")
                    st.caption("Nothing unusual happens in this situation, so both agents pay correctly.")
                st.caption("It adds up all wallets, retries after a timeout, keeps no batch memory and accepts "
                           "new bank details. " + " ".join((typ or {}).get("notes", [])[:1]))
            with right.container(border=True):
                st.markdown("**FairRun**")
                st.markdown(f"## ✅ {label}" if color != "red" else f"## 🛑 {label}")
                good = ["Paid only from this employer's own wallet." if res.paid else "No money moved."]
                if res.held:
                    good.append(f"Held {', '.join(res.held)} before any money left.")
                if res.escalated:
                    good.append("Shortfall split fairly and escalated to a human.")
                if last.get("fix"):
                    good.append(f"Smallest fix (Z3 optimiser): deposit **{to_major(last['fix'])} "
                                f"{employer(last['emp']).wallet_currency}** into {S.names[last['emp']]}'s own wallet "
                                "and everyone is paid in full.")
                for g in good:
                    st.markdown(f"- :green[{g}]")
                if res.plan is not None and res.paid:
                    wc = employer(last["emp"]).wallet_currency
                    nfx = sum(1 for c in res.plan.conversions if c != wc)
                    st.caption(f"Airwallex calls in this run: {nfx} FX conversion{'s' if nfx != 1 else ''}, "
                               f"{len(res.paid)} transfer{'s' if len(res.paid) != 1 else ''}, 1 platform charge, all "
                               "on this employer's own connected account.")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Decided and paid in", f"{last['ms']:.0f} ms", help="Whole run on the mock, measured now.")
            m2.metric("Z3 maths check", f"{res.z3_ms:.0f} ms", help="Time spent proving the plan against the rules.")
            m3.metric("Other employers' wallets touched", last["touched"])
            m4.metric("Audit entries added", last["entries"])
            for cid, q in res.approvals.items():
                if q.get("released"):
                    continue
                got = ", ".join(ROLE_TEXT[r] for r in q["valid"]) or "none yet"
                st.markdown(f"**{cid}: new bank details need 2 of 3 independent approvals** "
                            f"({' · '.join(ROLE_TEXT[r] for r in ROLES)}). Valid so far: {got}. "
                            "One stolen login is never enough. Try it in **Try to cheat FairRun → 5**.")
            for cid in res.held:
                if cid not in res.approvals:
                    st.markdown(f"**{cid}:** approvals alone cannot release this hold, because the new account is also "
                                "paid by another employer. New bank details normally need 2 of 3 independent "
                                "approvals: see **Try to cheat FairRun → 5**.")
            fc = last["first_check"]
            if fc is not None:
                broken = set(fc.get("broken", []))
                chips = " ".join((":red-badge[✗ " if r in broken else ":green-badge[✓ ") + RULE_TEXT[r] + "]"
                                 for r in RULES)
                st.markdown("**Maths check (Z3) on the full plan:** " + chips)
                if broken and res.status == "PAID_PARTIAL":
                    st.caption("The full plan failed, so FairRun computed the fairest plan from this employer's own "
                               "money only, re-checked it, and paid that.")
            if res.paid:
                st.markdown("**Paid:** " + ", ".join(f"{cid} ({to_major(v)})" for cid, v in res.paid.items()))
            if res.held:
                for cid, why in res.held.items():
                    st.warning(f"**Held for a human check, not paid: {cid}.** {why}")
            if res.escalated:
                st.info(res.escalated)
            with st.expander("Step-by-step reasoning", expanded=True):
                for line in res.explanation:
                    st.markdown(f"- {line}")
        if S.moved and last["emp"] is None:
            st.error("Nothing in FairRun's own flow caused this. Now see who notices ↓")

    # ---------------------------------------------------------------------------
    # Quantum Day
    # ---------------------------------------------------------------------------
    if S.quantum:
        q = S.quantum
        st.subheader("Quantum Day: can data stolen today be opened later?")
        st.markdown(
            "In February 2026 Citi estimated that a quantum-enabled attack on a top US bank could cause "
            "**$2.0 to 3.3 trillion** of damage ([American Banker](https://www.americanbanker.com/news/"
            "citi-banks-face-3-trillion-risk-from-quantum-cyberattacks)). FairRun cannot protect bank networks. "
            "It protects what it holds: workers' bank details and its own signed records. The danger that exists "
            "*today* is **harvest now, decrypt later**: attackers copy encrypted data now and open it years later.")
        st.info("**Simulation.** We cannot run Shor's algorithm here, so we hand the attacker the classical private "
                "keys, exactly what a quantum computer would recover. Everything else is FairRun's real encryption "
                "and signing code, attacked with the same stolen data.")

        h = q["hndl"]
        st.markdown("#### 1 · Stolen encrypted bank details")
        st.caption(f"What the attacker copied today: `{h['stolen_ciphertext']}` (unreadable)")
        a, b = st.columns(2)
        with a.container(border=True):
            st.markdown("**Classical-only lock** (what most systems use)")
            st.markdown(":red-badge[✗ opened on Q-Day]" if h["classical_read"] else ":green-badge[✓ still sealed]")
            if h["classical_read"]:
                st.code(f"attacker reads: {h['classical_read']}", language=None)
        with b.container(border=True):
            st.markdown("**FairRun hybrid lock** (X25519 + ML-KEM-768)")
            st.markdown(":red-badge[✗ opened on Q-Day]" if h["hybrid_read"] else ":green-badge[✓ still sealed]")
            st.caption(h["hybrid_error"] or "")

        f = q["forgery"]
        st.markdown("#### 2 · A forged audit seal")
        a, b = st.columns(2)
        with a.container(border=True):
            st.markdown("**Classical signature only** (Ed25519)")
            st.markdown(":red-badge[✗ forgery accepted]" if f["classical_accepts_forgery"] else ":green-badge[✓ forgery rejected]")
            st.caption("With the stolen classical key, a record can be rewritten and re-signed.")
        with b.container(border=True):
            st.markdown("**FairRun hybrid signature** (Ed25519 + ML-DSA-65)")
            st.markdown(":red-badge[✗ forgery accepted]" if f["fairrun_accepts_forgery"] else ":green-badge[✓ forgery rejected]")
            st.caption("Both signatures must verify. The forger has the classical one, not the post-quantum one.")

        m = q["migration"]
        st.markdown("#### 3 · Changing algorithms without a rewrite")
        st.markdown(f":green-badge[✓ {m['keys_rewrapped']} employer keys moved from {m['from']} to {m['to']}] "
                    f"· stored data untouched and still readable: **{m['data_untouched']}**")
        st.caption("NIST warns migration to post-quantum cryptography will take years. Every FairRun key and "
                   "signature carries an algorithm id, so upgrading is a rotation, not a rebuild.")

        st.markdown("**What this does and does not show**")
        st.markdown(
            "- It shows FairRun's own stored data and signed records are built to survive a quantum computer.\n"
            "- It does **not** fix systemic risk to bank networks such as Fedwire.\n"
            "- No quantum computer that can do this exists yet. The survey Citi cites puts the chance by 2034 at "
            "19 to 34%. Data that must stay private for many years is why it matters now.\n"
            "- The zero-knowledge balance proof keeps balances private even against quantum computers, but its "
            "'cannot be cheated' guarantee rests on elliptic curves and is **not** yet quantum-safe.\n"
            "- FairRun's connection to Airwallex uses TLS, which is outside FairRun's control.")
        with st.expander("The algorithms, in plain words and technical words"):
            show_table([{"What": w, "Technical": t, "In plain words": p, "Quantum note": n}
                      for w, t, p, n in ALGORITHMS])

    # ---------------------------------------------------------------------------
    # Proof of segregated funds
    # ---------------------------------------------------------------------------
    st.subheader("Proof of segregated funds")
    st.caption("Every employer checks, on its own, that its money is really in its own account, without seeing "
               "anyone else's balance. A total-only check (what exchanges publish) cannot see a secret move between "
               "accounts.")

    if S.want_proof:
        t0 = time.time()
        with st.spinner("Building the zero-knowledge proof and letting each employer verify it…"):
            proof = S.prover.prove(S.book, S.aw)
            results = {}
            for acct in S.accts:
                ip = S.prover.inclusion_proof(proof, acct)
                ok, msg = verify_zk_inclusion(ip, S.prover.public_keys, S.aw.get_balances(acct))
                results[acct] = (ok, msg)
            S.proof, S.proof_view, S.proof_version = proof, results, S.version
            S.proof_seconds = round(time.time() - t0, 1)
        S.want_proof = False

    if S.proof is None:
        st.info("Click **Check every employer's proof** (or situation 6) to build it.")
    else:
        pr = S.proof
        if S.proof_version != S.version:
            st.warning("Balances changed since this proof was built. Click **Check every employer's proof** again.")
        left, right = st.columns(2)
        seg = pr["statement"]["segregated"]
        shorts = []
        for b in pr["breaches"]:
            e, c = b.split(":")
            gap = S.book.owed.get(e, {}).get(c, 0) - S.aw.get_balances(e).get(c, 0)
            shorts.append(f"{S.names.get(e, e)} is short by {to_major(gap)} {c}")
        with left.container(border=True):
            st.markdown("**Without FairRun:** total-only check (proof of reserves)")
            st.markdown("## ✅ All fine" if pr["pooled_ok"] else "## ❌ Short")
            st.caption("Is the total money ≥ the total owed? The secret move does not change the total.")
        with right.container(border=True):
            st.markdown("**With FairRun:** every employer, every currency")
            st.markdown("## ✅ All fine" if seg else "## 🚨 " + "; ".join(shorts))
            st.caption("Is each employer's own money ≥ what that employer is owed? (Z3 rule R5)")
        st.markdown("**Each employer verifies its own proof, offline:**")
        pcols = st.columns(3)
        for col, acct in zip(pcols, S.accts):
            ok, msg = S.proof_view[acct]
            with col.container(border=True):
                st.markdown(f"**{S.names[acct]}**")
                st.markdown(":green-badge[✓ my money is safe]" if ok else ":red-badge[✗ my money is missing]")
                st.caption(msg)
        st.caption(f"Signed with {pr['statement']['scheme'].split('/')[0]} commitments and a hybrid "
                   f"Ed25519 + ML-DSA signature · built and verified in {getattr(S, 'proof_seconds', '?')} s here · "
                   "each employer sees only a scrambled code for everyone else.")

    # ---------------------------------------------------------------------------
    # Audit log
    # ---------------------------------------------------------------------------
    st.subheader("Audit log")
    ok, bad = S.fr.ledger.verify_chain()
    entries = S.fr.ledger.entries()
    a, b = st.columns(2)
    a.metric("Entries recorded", len(entries))
    b.metric("Tamper check", "intact ✓" if ok else f"broken at #{bad}")
    with st.expander("Latest entries"):
        for seq, kind, emp, body in entries[-12:][::-1]:
            who = S.names.get(emp, emp)
            st.code(f"#{seq} {kind:10} {who}: {str(body)[:160]}", language=None)


# ---------------------------------------------------------------------------
# Try to cheat FairRun
# ---------------------------------------------------------------------------
CAUGHT = ":green-badge[✓ Caught by FairRun]"

with cheat:
    if S.want_attack == "hide":
        with st.spinner("Building a zero-knowledge proof to attack…"):
            proof = S.prover.prove(S.book, S.aw)
            S.attacks["hide"] = hide_money(S.prover, proof)
        S.want_attack = None

    tried = [a for a in S.attacks.values() if a.get("caught") is not None]
    top = st.columns([3, 1])
    if tried:
        top[0].markdown(f"### FairRun {sum(1 for a in tried if a['caught'])} · "
                        f"Attackers {sum(1 for a in tried if not a['caught'])}")
    else:
        top[0].markdown("### Six attacks. None tried yet.")
    top[1].button("Run all six attacks", on_click=atk_all, type="primary", key="a_all", use_container_width=True)
    st.write("Pick an attack, or run all six. Each one runs against FairRun's real checks, on a copy, so the "
             "story is never damaged.")

    r1, r2, r3 = st.columns(2), st.columns(2), st.columns(2)
    with r1[0].container(border=True):
        st.markdown("#### 1 · Steal from another employer")
        st.write("Bright can't cover payroll. Pay Bright's workers from Alpha's wallet instead.")
        st.button("Launch attack", key="a1", on_click=atk_wallet)
        a = S.attacks.get("wallet")
        if a:
            st.markdown(CAUGHT if a["caught"] else ":red-badge[✗ Not caught]")
            st.markdown("Z3 broke: " + " ".join(f":red-badge[{r}]" for r in a["rules"]))
            for d in a["detail"]:
                st.caption(d)
            st.caption("Z3 reports every rule you broke, not just the first.")

    with r1[1].container(border=True):
        st.markdown("#### 2 · Rewrite history")
        st.write("Change a recorded payment in the audit log to ten times its amount.")
        st.button("Launch attack", key="a2", on_click=atk_log)
        a = S.attacks.get("log")
        if a and a["caught"] is not None:
            st.markdown(CAUGHT if a["caught"] else ":red-badge[✗ Not caught]")
            st.write(f"You changed {a['contractor']}'s payment from {a['old']} to {a['new']} {a['currency']}.")
            st.caption(f"Simple edit: caught at entry #{a['naive_flag']}.")
            st.caption(f"Clever edit, re-computing that entry's own hash: caught at entry #{a['clever_flag']}, "
                       "because the next entry still points to the original.")
            st.caption(f"Quietly deleting the newest entries: caught at entry #{a['cut_flag']}, because the log "
                       "no longer ends where its anchor says.")

    with r2[0].container(border=True):
        st.markdown("#### 3 · Hide money in the proof")
        st.write("Make the platform owe an employer 1.00 less, or hide a debt behind a negative amount.")
        st.button("Launch attack", key="a3", on_click=atk_hide)
        a = S.attacks.get("hide")
        if a and a["caught"] is not None:
            st.markdown(CAUGHT if a["caught"] else ":red-badge[✗ Not caught]")
            who = S.names.get(a["employer"], a["employer"])
            st.caption(f"Owe {who} 1.00 {a['currency']} less: rejected ({a['lower_msg']}).")
            st.caption("Prove a balance of -5,000.00: impossible, no valid range proof exists"
                       if not a["negative_possible"] else "Negative proof was possible!")
            st.caption("Reuse a valid proof for a negative amount: " +
                       ("accepted!" if a["swap_accepted"] else "rejected."))

    with r2[1].container(border=True):
        st.markdown("#### 4 · Be the quantum attacker")
        st.write("You stole encrypted bank details. It's Q-Day: you recover the classical private keys "
                 "(simulated, as Shor's algorithm would).")
        st.button("Launch attack", key="a4", on_click=atk_quantum)
        a = S.attacks.get("quantum")
        if a:
            st.markdown(CAUGHT if a["caught"] else ":red-badge[✗ Not caught]")
            st.caption(f"Classical-only lock: you read {a['classical_read']}. FairRun's hybrid lock: "
                       f"still sealed ({a['hybrid_error']}).")
            st.caption("Forged audit seal: " + ("accepted" if a["classical_forgery"] else "rejected") +
                       " by a classical-only check, " + ("accepted" if a["fairrun_forgery"] else "rejected") +
                       " by FairRun.")
            z = a["sizes"]
            st.markdown("**The price of quantum safety, measured:**")
            show_table([
                {"What": "Signature", "Classical": f"Ed25519: {z['ed25519_signature_bytes']} B",
                 "Post-quantum": f"ML-DSA-65: {z['ml_dsa_signature_bytes']:,} B",
                 "Bigger by": f"{z['ml_dsa_signature_bytes'] / z['ed25519_signature_bytes']:.0f}x"},
                {"What": "Key exchange", "Classical": f"X25519: {z['x25519_share_bytes']} B",
                 "Post-quantum": f"ML-KEM-768: {z['ml_kem_ciphertext_bytes']:,} B",
                 "Bigger by": f"{z['ml_kem_ciphertext_bytes'] / z['x25519_share_bytes']:.0f}x"}])
            st.caption("FairRun signs a whole run once (one Merkle root), so the bigger signature is paid once per "
                       "run, not once per payment.")

    with r3[0].container(border=True):
        st.markdown("#### 5 · Be a payroll pirate")
        st.write("Like the real 2025-26 attacks: you took over Tom's login. Change his bank account and get his pay.")
        st.button("Launch attack", key="a5", on_click=atk_pirate)
        a = S.attacks.get("pirate")
        if a:
            st.markdown(CAUGHT if a["caught"] else ":red-badge[✗ Not caught]")
            for x in a["steps"]:
                mark = "💸 paid" if x["paid"] else "⛔ held"
                st.caption(f"{mark} · {x['step']} → {x['why']}")
            st.caption("Rule: new bank details need 2 of 3 independent, signed approvals (employer, platform call-back "
                       "to the phone on file, contractor). One role, one vote; each approval is bound to that exact "
                       "request and account; signatures are hybrid Ed25519 + ML-DSA.")
    with r3[1].container(border=True):
        st.markdown("#### 6 · Move money in, then spend it")
        st.write("Secretly move 2,000 USD from Cedar into Alpha's wallet, then run Alpha's payday, so Cedar's "
                 "money is spent on Alpha's wages before anyone looks.")
        st.button("Launch attack", key="a6", on_click=atk_launder)
        a = S.attacks.get("launder")
        if a:
            st.markdown(CAUGHT if a["caught"] else ":red-badge[✗ Not caught]")
            st.caption(f"Typical agent spent {to_major(a['typical_spent'])} USD of Cedar's money on Alpha's wages. "
                       f"FairRun spent {to_major(a['fairrun_spent'])} USD of it: {a['detail']}.")
            st.caption(a["line"])
            st.caption("Rule: FairRun spends only money its own records explain (recorded deposits and its own "
                       "actions). Anything else in a wallet is quarantined and escalated.")



# ---------------------------------------------------------------------------
# Your own case: the viewer chooses every number
# ---------------------------------------------------------------------------
@st.cache_resource
def theorems() -> dict:
    return {**prove_lemmas(), **prove_no_borrowing()}


PEOPLE = {e.employer_id: [(c.contractor_id, c.currency, c.amount) for c in e.contractors] for e in build_world()[1]}

with own:
    st.subheader("Not scripted: design your own payday")
    st.write("Choose every number yourself. Both agents then run live on identical copies of your case, and a "
             "neutral referee reads what really happened from the Airwallex records.")
    with st.form("own_case"):
        c1, c2, c3 = st.columns(3)
        b_alpha = c1.number_input("Alpha Studio wallet (USD)", 0.0, 1_000_000.0, 15000.0, step=100.0)
        b_bright = c2.number_input("Bright Bakery wallet (GBP)", 0.0, 1_000_000.0, 700.0, step=100.0)
        b_cedar = c3.number_input("Cedar Labs wallet (USD)", 0.0, 1_000_000.0, 9000.0, step=100.0)
        by_name = {v: k for k, v in S.names.items()}
        who = by_name[st.selectbox("Whose payday is it?", list(by_name), index=1)]
        st.caption("Pay amounts (all three employers' workers are listed; only the chosen employer's are paid)")
        pay = {}
        cols = st.columns(4)
        i = 0
        for acct, people in PEOPLE.items():
            for cid, cur, amt in people:
                pay[cid] = cols[i % 4].number_input(f"{cid} ({cur})", 0.0, 1_000_000.0, amt / 100, step=50.0,
                                                    key=f"pay_{cid}")
                i += 1
        st.caption("Add trouble")
        t1, t2, t3 = st.columns(3)
        timeout = t1.checkbox("A payment times out after Airwallex accepted it")
        replay = t2.checkbox("The same payroll is triggered twice")
        pirate = t3.selectbox("An attacker changes this worker's bank account",
                              ["nobody"] + [cid for people in PEOPLE.values() for cid, _, _ in people], index=4)
        m1, m2, m3 = st.columns(3)
        mv_amount = m1.number_input("Secretly move this many USD…", 0.0, 1_000_000.0, 500.0, step=50.0)
        mv_src = by_name[m2.selectbox("…from", [S.names["acct_cedar"], S.names["acct_alpha"]])]
        mv_dst = "acct_alpha" if mv_src == "acct_cedar" else "acct_cedar"
        m3.markdown(f"…to **{S.names[mv_dst]}**")
        go = st.form_submit_button("Run both agents on my case", type="primary")
    if go:
        spec = {"balances": {"acct_alpha": b_alpha, "acct_bright": b_bright, "acct_cedar": b_cedar},
                "amounts": pay, "employer": who, "timeout": timeout, "replay": replay,
                "pirate": pirate if pirate in [c for c, _, _ in PEOPLE[who]] else None,
                "move": (mv_src, mv_dst, mv_amount) if mv_amount > 0 else None}
        S.own_result = (spec, run_custom(spec))
        if pirate != "nobody" and spec["pirate"] is None:
            st.caption(f"{pirate} does not work for {S.names[who]}, so the bank change does not affect this payday.")
    if S.get("own_result"):
        spec, r = S.own_result
        a, b = st.columns(2)
        for col, key, title in ((a, "typical", "Typical agent (our simple baseline)"), (b, "fairrun", "FairRun")):
            x = r[key]
            st_ = x["stats"]
            bad = (st_.get("double_payments", 0) + st_.get("paydays_using_others_money", 0)
                   + st_.get("paid_to_attacker", 0) + (1 if x["move"] and not x["move"]["caught"] else 0)
                   + (1 if x.get("spent_moved") else 0))
            with col.container(border=True):
                st.markdown(f"**{title}**")
                st.markdown(f"## {'❌' if bad else '✅'} {bad} mistake{'s' if bad != 1 else ''}")
                st.caption("Referee, from the Airwallex records:")
                st.markdown(f"- Workers paid twice: **{st_.get('double_payments', 0)}**\n"
                            f"- Paydays using another employer's money: **{st_.get('paydays_using_others_money', 0)}**\n"
                            f"- Payments to the attacker's account: **{st_.get('paid_to_attacker', 0)}**\n"
                            f"- Workers paid correctly: **{st_.get('correct_payments', 0)}**")
                if x["move"]:
                    st.markdown(("- Secret move: :green[**noticed**] — " if x["move"]["caught"]
                                 else "- Secret move: :red[**not noticed**] — ") + x["move"]["detail"])
                    st.markdown(f"- Secretly moved-in money spent: **{to_major(x.get('spent_moved', 0))} USD**")
                elif spec.get("move"):
                    st.caption("No secret move happened: the source wallet was empty.")
                st.caption("Wallets afterwards: " + " · ".join(
                    f"{S.names[acct]} {money(bal)}" for acct, bal in x["balances"].items()))
                for issue in x["issues"]:
                    st.markdown(f"- :red[{issue}]")
                with st.expander("What it did, step by step"):
                    st.caption(f"Result: {x['status']}")
                    for line in x["lines"]:
                        st.markdown(f"- {line}")

    st.divider()
    st.subheader("Proved for every case, not only the ones you try")
    st.write("Z3 proves these for **all** amounts and balances (symbolic numbers), not for chosen examples. "
             "For each one, it also finds a concrete failure when the rule is removed.")
    th = theorems()
    ok = ":green-badge[✓ proved]"
    cx = th["without_R1"]
    st.markdown(f"{ok} **T3 · A checked plan can never take another employer's money.** If a plan passes rules R1 "
                f"and R2, every other employer's balance is unchanged afterwards and its own wallet is never "
                f"overdrawn ({th['payouts']} payouts, {th['employers']} employers, any amounts). Without R1, Z3 finds "
                f"a failure: balances {cx['balances']} become {cx['after']}.")
    g = th["T2_solvent_not_segregated_example"]
    st.markdown(f"{ok} **T2 · Checking each employer is strictly stronger than checking the total.** Every employer "
                f"covered ⇒ total covered, but not the reverse: held {g['held']} against owed {g['owed']} passes a "
                "total-only check while an employer is short.")
    st.markdown(f"{ok} **T1 · No employer can be shown a balance that is not counted.** With non-negative sums, "
                f"every included balance ≤ the signed total. Without that check, Z3 hides a liability: leaves "
                f"{th['T1_attack_without_check']['leaves'][:2]}… sum to {th['T1_attack_without_check']['root']}.")


# ---------------------------------------------------------------------------
# Stress test: the same random paydays through both agents
# ---------------------------------------------------------------------------
def run_stress():
    S.stress = stress_test(int(S.stress_n), int(S.stress_seed))


with stress:
    st.subheader("Head to head on random paydays")
    st.write("Each case has random wallet balances and pay amounts, and random trouble: timeouts, replayed batches, "
             "hijacked bank details and secret moves between accounts. The **same** cases go through both agents. "
             "Change the seed for a completely different set: nothing here can be prepared in advance.")
    c1, c2, c3 = st.columns([1, 1, 2])
    c1.selectbox("Random cases", [50, 200, 500], index=1, key="stress_n")
    c2.number_input("Seed", 0, 10**9, 2026, key="stress_seed")
    c3.markdown("&nbsp;")
    c3.button("Run the stress test", type="primary", on_click=run_stress, key="stress_go")
    r = S.get("stress")
    if r:
        t, f = r["typical"], r["fairrun"]
        tr = r["trouble"]
        st.caption(f"{r['cases']} random cases (seed {r['seed']}) · {t.get('paydays', 0)} paydays · trouble injected: "
                   f"{tr['timeouts']} timeouts, {tr['replays']} replays, {tr['bank_changes']} hijacked bank details, "
                   f"{tr['secret_moves']} secret moves")
        a, b = st.columns(2)
        tot_t = sum(t.get(k, 0) for k, _ in METRICS)
        tot_f = sum(f.get(k, 0) for k, _ in METRICS)
        with a.container(border=True):
            st.markdown("**Typical agent** (our simple baseline)")
            st.markdown(f"## ❌ {tot_t} mistakes")
        with b.container(border=True):
            st.markdown("**FairRun**")
            st.markdown(f"## {'✅' if tot_f == 0 else '❌'} {tot_f} mistakes")
        rows = [{"What the referee counted": label, "Typical agent": t.get(k, 0), "FairRun": f.get(k, 0)}
                for k, label in METRICS]
        rows.append({"What the referee counted": "Workers paid correctly",
                     "Typical agent": t.get("correct_payments", 0), "FairRun": f.get("correct_payments", 0)})
        show_table(rows)
        st.markdown(f"Money that went wrong with the typical agent: **{to_major(t.get('double_usd', 0))} USD** paid "
                    f"twice, **{to_major(t.get('others_money_usd', 0))} USD** taken from other employers, "
                    f"**{to_major(t.get('attacker_usd', 0))} USD** sent to attackers. With FairRun: "
                    f"**{to_major(f.get('double_usd', 0) + f.get('others_money_usd', 0) + f.get('attacker_usd', 0))} USD**.")
        st.caption(f"FairRun did not get there by refusing to pay: {f.get('fr_PAID_FULL', 0)} paydays paid in full, "
                   f"{f.get('fr_PAID_PARTIAL', 0)} split fairly from the employer's own money and escalated, "
                   f"{f.get('fr_replays_blocked', 0)} replays blocked, {f.get('fr_held', 0)} suspicious payouts held, "
                   f"{f.get('fr_unreconciled', 0)} runs failing reconciliation.")
    st.caption("The baseline is our own simple agent, not a real product: it adds up all wallets, tops a short wallet "
               "up from the others, retries after a timeout with a new request id, keeps no batch memory, accepts "
               "new bank details, and checks totals only. Code: `fairrun/baseline.py`. Reproduce from a terminal: "
               "`python -m scenarios.stress_run 200 2026`. Offline rules only; no AI calls are made in this test.")
