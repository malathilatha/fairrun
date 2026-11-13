# FairRun

A payroll agent for multi-employer platforms that **never uses one employer's money to pay another employer's contractors**.
Built for the Airwallex Agentic Banking Hackathon, Kit 6 (Multi-Employer Payroll Executor).

> Status: the full story runs end to end on the **real Airwallex sandbox** (three connected accounts)
> and on an offline mock with the same interface.

## The problem

When one platform runs payroll for many employers, an agent that adds up balances across employers can approve
payroll that a short employer cannot fund, quietly using another employer's money. In 2019 MyPayrollHR's owner redirected
employers' payroll money into accounts he controlled; several thousand people did not get paid (US DOJ). FairRun checks every employer against **its own wallet only**.

The same failures are still happening:

| Real incident | FairRun's answer (dashboard situation) |
|---|---|
| Synapse (2025): the US CFPB sued, alleging records did not show where customers' money was; a $60-90M gap ([PYMNTS](https://www.pymnts.com/legal/2025/synapse-faces-cfpb-over-fund-reconciliation-gaps/)) | Per-employer proof of segregated funds (6) |
| "Payroll pirates" (2025-26): one hijacked login changes bank details and takes a salary ([The Register](https://www.theregister.com/2026/02/11/payroll_pirates_business_social_engineering/)) | Hold on bank change + 2-of-3 signed approvals (5, cheat 5) |
| Payroll data stolen via an ADP partner serving the Middle East (2025) ([Slashdot / The Register](https://tech.slashdot.org/story/25/05/16/1422227/)) | Per-employer encryption, hybrid post-quantum key wrapping (7) |
| 89% of payroll staff hit payment issues in a year ([Finity, 2026](https://onrec.com/news/news-archive/9-in-10-payroll-professionals-experience-errors-finity-research-uncovers-near)) | Z3 pre-checks, idempotent retries, reconciliation (1, 4) |
| UK unpaid-wage claims at an eight-year high, 2025/26 ([HRreview](https://www.pulse.bot/human-resources/news/unpaid-wage-claims-hit-eight-year-high-as-business-failures-rise-bad8ea85-5b36-44c9-90eb-46dac3531bd8/)) | Fair split from the short employer's own money (2) |

Synapse was a banking middleware firm, not a payroll company: it is the same failure pattern, not the same business.

## FairRun against a typical agent (`fairrun/baseline.py`)

To show the difference instead of claiming it, the repo includes a baseline: **our own** simple "typical payroll
agent" (not a real product). It adds up all wallets, tops a short wallet up from other employers, retries after a
timeout with a new request id, keeps no batch memory, accepts changed bank details, and checks totals only.
Both agents run on identical copies of the same world, and a neutral referee counts what really happened from the
(mock) Airwallex records, not from what either agent reports.

`python -m scenarios.stress_run 200 2026` (200 random cases: random balances and pay, random timeouts, replays,
hijacked bank details and secret moves; 650 paydays):

| What the referee counted | Typical agent | FairRun |
|---|---|---|
| Workers paid twice (timeouts and replays) | 74 | 0 |
| Paydays that used another employer's money | 212 | 0 |
| Payments sent to an attacker's bank account | 58 | 0 |
| Secret money moves not noticed | 52 | 0 |
| Workers paid correctly | 1,112 | 1,335 |

FairRun did not get there by refusing to pay: 350 paydays were paid in full, 250 were split fairly from the
employer's own money and escalated, 50 replays were blocked and 65 suspicious payouts were held. Change the seed
for a different set of cases. The dashboard has the same test, a side-by-side view in every situation, and a
"Your own case" tab where the viewer sets every number.

How FairRun compares with common approaches:

| Common approach | What FairRun adds |
|---|---|
| An AI model with payment tools decides | Z3 rules decide; the model can only make a run stricter |
| Total-only proof of reserves | Per-employer, per-currency proof; each employer verifies its own part |
| E-mail or call-back confirmation of bank changes | 2 of 3 independent signed approvals, bound to the exact change |
| Classical-only encryption and signatures | Hybrid post-quantum key wrapping and signatures |

### Proved for all cases (`fairrun/verifier.py`, `fairrun/solvency.py`)

Z3 proves three statements for symbolic (any) amounts and balances, and shows a concrete failure when a rule is
dropped: **T1** no included balance can exceed the signed total; **T2** per-employer segregation implies total
solvency but not the reverse; **T3** a plan that passes R1 and R2 leaves every other employer's balance unchanged
and never overdraws its own wallet (bounded: 4 payouts, 3 employers). When a plan fails R2, Z3's optimiser gives
the smallest deposit into that employer's own wallet that would make it pass.

## Built on Airwallex

| Airwallex capability | How FairRun uses it |
|---|---|
| Connected accounts | One account per employer: the basis of segregation |
| `x-on-behalf-of` | Every call is scoped to exactly one employer |
| Multi-currency wallets and FX conversions | One conversion per currency, re-checked against the real cost |
| Transfers with `request_id` | Safe retries: look up by `request_id` before any re-send |
| Platform charges | FairRun's fee, taken from the same employer's own account |

## 2-of-3 approval for bank changes (`fairrun/approvals.py`)

A payout to new bank details is released only when 2 of 3 independent parties have signed an approval of exactly
that change: the employer's payroll admin, the platform's call-back to the phone already on file, and the contractor.
Each approval is a hybrid Ed25519 + ML-DSA-65 signature over {request id, employer, contractor, blind index of the
new account}, so it cannot be reused for another request or account. One role counts once; unregistered keys count
for nothing. A hold for any other reason (for example, the account is also paid by another employer) cannot be
released by approvals. Held bank details are never remembered as trusted. In the demo FairRun generates all three
keys to play every party; in production each party keeps its own private key.

## What happens in a run

1. **Fraud checks**: a changed bank account, or an account paid by more than one employer, is held for a human.
   Cross-employer matching uses a blind index (keyed HMAC), so account numbers are never compared in the clear.
2. **Price**: fees are calculated before FX, one conversion per currency (builder-guide rule).
3. **Verify (Z3)**: the plan must pass four named rules, and every broken rule is reported:
   - R1 own funds only, R2 within that wallet's balance, R3 batch not replayed, R4 one payout per contractor
4. **Shortfall**: if R2 fails, OR-Tools computes a fair partial run (the same, highest possible % for everyone),
   re-verifies it, and escalates the rest. Other employers' funds are never considered.
5. **Pay safely**: an intent is recorded before every money call. On a timeout, FairRun looks the transfer up by
   `request_id` before doing anything, so it never pays twice and never pays blind.
6. **Fee and reconcile**: the platform fee is charged from that employer's wallet, then its balances are reconciled.
7. **Audit**: every step goes into a hash-chained log. Editing, deleting or reordering an entry is detected.

## The agents (`fairrun/agent.py`)

- **Planner agent** (Claude Sonnet): reads contractor messages, e.g. "pay my new account today, urgent",
  and flags bank-change requests. Code then forces a hold for an out-of-band check, whatever the model says.
  It also writes the plain-English summary of each run, using only the engine's facts.
- **Reviewer agent** (Claude Haiku): reviews each plan after Z3 passes and before any money moves.
  It has no tools and cannot pay. A REJECT blocks the batch; an APPROVE cannot override Z3.

Without `ANTHROPIC_API_KEY`, both fall back to fixed rules, so the demo and tests run offline.
Rules and amounts always live in code; the models never decide how much is paid.

## Security layer (`fairrun/crypto.py`, `fairrun/audit.py`)

| What | How | Why it matters |
|---|---|---|
| Per-employer encryption | Each employer's contractor bank data has its own AES-256-GCM key; the employer id is bound into every ciphertext | Fund separation becomes data separation: Bright's key cannot open Alpha's records |
| Post-quantum key wrapping | Each employer key is wrapped with hybrid X25519 + ML-KEM-768 | Stored bank data stays safe against "harvest now, decrypt later" |
| Crypto-shredding | Destroying an employer's key makes all its stored data unreadable | Instant, verifiable deletion when an employer leaves |
| Blind index | Keyed HMAC fingerprints of bank accounts | Cross-employer fraud matching without decrypting anyone's data |
| Sealed audit log | Hash-chained entries; each run's Merkle root signed once with Ed25519 + ML-DSA-65 (both must verify) | Tamper-evident history; one 3.3 KB PQ signature per run, not per entry |
| Private receipts | Each employer gets its own entries plus Merkle proofs | It can verify its history without seeing other employers' entries |
| Crypto-agility | Every key and signature carries an algorithm id; rotation re-wraps keys (ML-KEM-1024) and re-signs seals (ML-DSA-87) | Algorithms can change without a rewrite; old receipts still verify |

Keys are held in memory for the demo; production would keep master keys in a KMS/HSM.

## Proof of Segregated Funds (`fairrun/solvency.py`)

Crypto exchanges publish *proof of reserves*: total assets >= total liabilities. That is too weak for payroll:
a platform passes it while covering one employer's hole with another employer's money, because the total
does not change. FairRun proves the per-employer statement instead:

> for every employer *e* and currency *c*: **held(e, c) >= owed(e, c)**, where *held* is the live balance of
> *e*'s own Airwallex connected account and *owed* is what FairRun's books say *e* has.

- **Merkle sum tree** over what is owed. Each node hashes both child hashes and both child sums; negative sums
  are rejected (early designs hashed only the parent total, which lets an operator hide liabilities).
  Leaves are salted and shuffled.
- **Z3 rule R5_segregated** checks every (employer, currency) and names every breach.
- The statement is **signed once** with the hybrid Ed25519 + ML-DSA signer.
- Each employer gets a **private inclusion proof**, verifies it offline, and compares the amount with its own
  Airwallex dashboard balance.
- **Two theorems are proved with Z3** for all balances in an 8-leaf tree, not tested on examples:
  - T1: with non-negative sums, every included balance <= the signed total. Without the check, Z3 finds the
    attack (a fake negative leaf hides a real liability).
  - T2: per-employer segregation implies total solvency, but not the reverse. Z3 produces a case where totals
    balance while one employer is short: exactly what a total-only proof misses.

Demo: an operator moves 500 USD from Cedar's account to Alpha's outside FairRun. The total-only check
**passes**; FairRun's proof **fails** and names `acct_cedar:USD`; Cedar's own offline check reports "short 500.00 USD".

### Zero-knowledge version (`fairrun/zk_solvency.py`)

A plain Merkle sum proof leaks: Alpha's proof shows its siblings' sums, so with few employers it can work out
Bright's balance. FairRun's ZK version (in the style of DAPOL+, Ji & Chalkias, ACM CCS 2021) hides them:

- Every amount in the tree is a **Pedersen commitment** on secp256k1 (`v*G + r*H`): hiding and binding.
  Commitments add up, so a parent is just the sum of its children, with no amounts visible.
- Every node an employer is shown carries a **zero-knowledge range proof** that its hidden amount is in [0, 2^40):
  bit commitments + Chaum-Damgard-Schoenmakers OR-proofs, made non-interactive with Fiat-Shamir. This is what
  enforces theorem T1 without revealing the numbers. A negative amount has no valid proof.
- Only the **total per currency** is revealed and signed. Each employer opens only its own leaf, every currency is
  committed for every employer (so holdings don't leak), and padding leaves look like real ones.

Each employer learns that its balance is inside the signed total and that everything else is non-negative,
and nothing about any other employer. Proving takes about 1-2 s and verifying about 0.6 s per employer
(about 50 KB) in pure Python.

Limits: the Pedersen commitments hide balances even against a quantum computer, but their *binding* (the platform
cannot open a commitment to a different value) rests on elliptic-curve hardness, which a future quantum computer
could break. The signatures and key wrapping are post-quantum hybrids; the commitments are not. A post-quantum
version would use lattice-based commitments. Also demo-grade, not constant-time, pure-Python curve code (production: a vetted library). Bulletproofs
(Bunz et al. 2018) would shrink each range proof from about 10 KB to about 0.7 KB. A proof is a snapshot at one
moment. The platform itself still sees everything (it is the prover). The number of leaves is visible. In
production the books would be kept from the ledger and Airwallex deposit webhooks.

## Run it (Windows PowerShell)

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

python -m scenarios.demo_run      # the full demo story on the mock
streamlit run dashboard/app.py    # the same story as a dashboard (six clicks)
python -m pytest -q               # 53 tests
python -m scenarios.stress_run 200 2026   # head-to-head stress test, any size and seed
```

Check the real sandbox connection:

```powershell
$env:AWX_CLIENT_ID="your-client-id"
$env:AWX_API_KEY="your-api-key"
python scripts/check_sandbox.py
```

To use the Claude agents, also set `$env:ANTHROPIC_API_KEY="..."` (or `set ANTHROPIC_API_KEY=...` in Command Prompt).

Never commit keys. Use environment variables or a local `.env` (already in `.gitignore`).

## Demo story (`scenarios/demo_run.py`)

| Step | What you see |
|---|---|
| Alpha Studio, normal run | USD wallet, EUR + USD contractors, SWIFT fees, one payout times out and is found, not re-sent |
| Bright Bakery, short | Z3 rejects R2, fair split pays 78.6% each, the rest is escalated |
| Cedar deposit lands mid-run | Bright's position is unchanged |
| Alpha batch replayed | Blocked by R3 and R4 |
| Bank-detail change | Tom's "urgent, new account" email is flagged by the planner agent; his payout is held, Sara is paid |
| Proof of Segregated Funds | Plain proof leaks a sibling's balance, the ZK proof shows only a commitment; every employer verifies its own; after a hidden 500 USD move from Cedar to Alpha, the total-only check passes and FairRun catches it |

## Quantum Day demo (`fairrun/quantum_demo.py`, dashboard situation 7)

Citi estimated in February 2026 that a quantum-enabled attack on a top US bank could cause $2.0-3.3 trillion of damage
([American Banker](https://www.americanbanker.com/news/citi-banks-face-3-trillion-risk-from-quantum-cyberattacks)).
FairRun cannot protect bank networks; it protects what it holds. The danger that exists today is **harvest now,
decrypt later**: attackers copy encrypted data now and open it once a quantum computer exists.

The demo attacks the same stolen data under two designs, using FairRun's real encryption and signing code:

| Attack | Classical-only design | FairRun hybrid design |
|---|---|---|
| Stolen encrypted bank details | Opened | Still sealed (X25519 + ML-KEM-768) |
| Forged audit seal | Accepted | Rejected (Ed25519 + ML-DSA-65, both must verify) |
| Migration | - | 3 employer keys moved to ML-KEM-1024 with no data rewrite |

**One thing is simulated:** Shor's algorithm. We hand the attacker the classical private keys, which is exactly what a
quantum computer would recover. No quantum computer that can do this exists yet; the 2024 Global Risk Institute survey
cited by Citi puts the chance by 2034 at 19-34%. AES-256 is not broken by Shor (Grover only halves its strength).
It does not fix systemic risk to bank networks, and the zero-knowledge proof's binding is not yet quantum-safe (see above).

## Dashboard (`dashboard/app.py`)

`streamlit run dashboard/app.py` shows the story as seven clicks, each opening with the real incident it replays and live numbers (time to decide, time in Z3, other employers' wallets touched: 0): each employer's own wallet, what FairRun decided
and why (the Z3 rules as green/red chips), the proof of segregated funds, and the audit log. The last click secretly
moves 500 USD between accounts: the total-only check still passes, FairRun's per-employer check fails, and only
Cedar's card turns red. It runs on the built-in mock so every click is repeatable; the same engine runs on the real
Airwallex sandbox with `python -m scenarios.real_run`.

## Try to cheat FairRun (dashboard tab)

Six attacks a judge can launch, each against FairRun's real checks and on a copy, so the story is never damaged:

| Attack | How FairRun catches it |
|---|---|
| Pay Bright's workers from Alpha's wallet | Z3 rejects the plan and names every broken rule (R1, R2) |
| Change a recorded payment to 10x, or quietly delete the newest entries | The hash chain flags the entry; re-computing its hash only moves the flag to the next entry; a cut-off tail no longer matches the log's anchor |
| Owe an employer 1.00 less, or hide a debt as a negative amount | The inclusion proof fails; a negative amount has no valid range proof |
| Be a payroll pirate: approve a bank change with one stolen login, repeat it, forge or copy approvals | Still held at 1 of 3 valid approvals; a genuine change with two independent approvals is paid |
| Move Cedar's money into Alpha's wallet, then run Alpha's payday so it is spent on wages | The extra money is quarantined: FairRun spends only money its own records explain (recorded deposits and its own actions) |
| Be the quantum attacker (Q-Day simulated) | The hybrid lock stays sealed and the forged seal is rejected; the cost is measured (ML-DSA-65 signatures are 3,309 B against Ed25519's 64 B, paid once per signed run) |

## Project layout

```
fairrun/
  models.py          data types (all money in integer minor units)
  pricing.py         fees, FX needs, deterministic batch keys
  verifier.py        Z3 plan check (R1-R4), theorem T3, smallest fix
  fair_split.py      OR-Tools fair partial run
  ledger.py          intent ledger + hash-chained log
  fraud.py           bank-change and blind-index cross-employer checks
  engine.py          the run: fraud -> price -> verify -> split -> pay -> fee -> reconcile
  airwallex_mock.py  mock with real sandbox quirks
  airwallex_real.py  real sandbox client (same interface)
  agent.py           planner + reviewer agents (Claude, with offline fallback)
  crypto.py          per-employer encryption, hybrid KEM wrapping, hybrid PQ signer
  audit.py           Merkle-sealed audit log and private per-employer receipts
  solvency.py        Proof of Segregated Funds (Merkle sum tree, Z3 R5 + theorems T1/T2)
  zk_solvency.py     zero-knowledge version: Pedersen commitments + range proofs
  ec.py              minimal secp256k1 arithmetic for the commitments
  quantum_demo.py    Q-Day simulation: harvest-now-decrypt-later, forged seal, migration
  approvals.py       2-of-3 signed approval for bank-detail changes
  baseline.py        the 'typical agent' baseline, the referee, the random stress test, 'your own case'
  attacks.py         the six 'try to cheat' attacks, all run on copies
dashboard/app.py     Streamlit dashboard
Dockerfile, deploy/  mock-only public demo on AWS EC2 (see deploy/DEPLOY_AWS.md)
scenarios/demo_run.py
scenarios/stress_run.py   head-to-head stress test from the terminal
scripts/check_sandbox.py
tests/test_core.py
```

## Compliance and limits

Not legal advice; rules differ by country.

- **Scope:** contractor payouts. FairRun does not calculate or withhold tax or file returns; it pays amounts the
  employer's payroll system has calculated and keeps the records. For employees, wage laws usually require full,
  on-time pay, so a hold or a fair partial run is escalated to a human, never treated as settled.
- **Record keeping:** payroll records must be kept for years (for example 4 years for US employment tax records,
  3 years for UK payroll records). `EmployerVault.keep_records_until` blocks crypto-shredding until then.
- **Privacy:** bank account numbers are masked (`mask_pii`) before any text is sent to the Claude agents; logs hold
  keyed fingerprints, not account numbers. Production use needs a data processing agreement with the model provider.
- **Licensing:** FairRun is not a money transmitter. Funds stay in each employer's own Airwallex account.
- **The proof is evidence, not an audit opinion.** VAT on platform fees is not handled.

## We attacked it ourselves (two rounds)

Before submitting we tried to break FairRun: random inputs, random clicks, and targeted attacks. Every hole below
was real, is now fixed, and has a regression test in `tests/test_core.py`.

| Attack that worked | Fix |
|---|---|
| Move another employer's money into a wallet, then run payday | Money the books cannot explain is quarantined, never spent |
| Slip the money in *during* a run so it looks like part of it | The books move only by what the run itself did, not by the balance change |
| Replay a paid batch under a re-spelled period (`2026-w45`, extra spaces, look-alike characters) | Period names are normalised before the replay check |
| Delete a worker and re-add them under a new id with the attacker's bank account | A new payee at an employer with history is held until 2 of 3 approve |
| Re-format a shared account number (`US 0001`, `us.0001`, look-alike characters) to dodge matching | Account fingerprints use letters and digits only, after Unicode folding |
| Two payees of one employer sharing one bank account (ghost worker) | Both are held |
| Send a broken approval to crash the run | A malformed approval counts as "no" |
| Quietly delete the newest audit-log entries | The log is checked against an anchor (entry count and newest hash) kept outside the database |
| Start the same payroll twice at the same moment | One run at a time; the second is blocked as a replay |
| Ask for a currency FairRun has no route for | Blocked cleanly, nothing paid |

## Honest notes

- FairRun is not unbeatable. Known limits: on an employer's very first run nobody has history, so onboarding
  checks must happen elsewhere; an attacker who controls two of the three approvers defeats 2-of-3; an insider
  who can write false deposits into the books defeats the quarantine (in production, deposits come from
  Airwallex webhooks); the one-run-at-a-time lock and the log anchor live in one process, so several servers
  would need a shared database lock and a published, signed anchor; and nothing here protects against someone
  who controls the server itself.
- The stress test, "your own case" and the cheat attacks run on the mock; the real sandbox is exercised by
  `scenarios/real_run.py`.
- The "typical agent" is our own baseline, written to behave like a simple agent with no independent controls.
  It is not a measurement of any real product.

- Z3 checks each **plan** against fixed rules. It does not prove the whole program is bug-free.
- FX rates, fees and contractor data in the mock are synthetic.
- `airwallex_real.py` follows the builder guide; confirm each call against the sandbox before relying on it.

## Next steps

- Keep the funds book continuously from the ledger and Airwallex deposit webhooks
