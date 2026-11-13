"""Intent ledger: ambiguity-safe payouts plus a hash-chained decision log.

Before any money call, FairRun writes an INTENT. After the call it writes the OUTCOME.
If a call times out, the outcome is unknown: FairRun looks the transfer up by request_id
before doing anything else, so it never pays without knowing what already happened.

Every entry stores the hash of the previous entry, so deleting, editing or reordering
any entry breaks the chain (tamper-evident). Signing the chain comes in a later step.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid

GENESIS = "0" * 64


def entry_hash(ts: float, kind: str, employer: str, body: dict, prev: str) -> str:
    payload = json.dumps({"ts": ts, "kind": kind, "employer": employer, "body": body,
                          "prev": prev}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class Ledger:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)  # Streamlit runs each click on its own thread
        self.db.execute("""CREATE TABLE IF NOT EXISTS log(
            seq INTEGER PRIMARY KEY, ts REAL, kind TEXT, employer TEXT,
            body TEXT, prev_hash TEXT, hash TEXT)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS intents(
            request_id TEXT PRIMARY KEY, employer TEXT, contractor TEXT, period TEXT,
            batch_key TEXT, currency TEXT, amount INTEGER, state TEXT)""")
        self.db.execute("CREATE TABLE IF NOT EXISTS batches(batch_key TEXT PRIMARY KEY, employer TEXT)")
        # Anchor kept OUTSIDE the database: how many entries this process wrote and the newest hash.
        # A hash chain alone cannot see its own tail being cut off; the anchor can.
        self._count = 0
        self._head = GENESIS

    # --- hash-chained log ------------------------------------------------
    def _last_hash(self) -> str:
        row = self.db.execute("SELECT hash FROM log ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def log(self, kind: str, employer: str, **body) -> str:
        prev = self._last_hash()
        ts = time.time()
        h = entry_hash(ts, kind, employer, body, prev)
        self.db.execute("INSERT INTO log(ts,kind,employer,body,prev_hash,hash) VALUES(?,?,?,?,?,?)",
                        (ts, kind, employer, json.dumps(body, sort_keys=True), prev, h))
        self.db.commit()
        self._count += 1
        self._head = h
        return h

    def anchor(self) -> tuple[int, str]:
        """(entries written, newest hash). In production this is what gets signed and handed out each run."""
        return self._count, self._head

    def verify_chain(self, anchor: tuple[int, str] | None = None) -> tuple[bool, int | None]:
        """Check every link, then check the log still ends where the anchor says (catches cut-off tails)."""
        count, head = anchor or (self._count, self._head)
        prev = GENESIS
        n = last = 0
        for seq, ts, kind, employer, body, prev_hash, h in self.db.execute(
                "SELECT seq,ts,kind,employer,body,prev_hash,hash FROM log ORDER BY seq"):
            if prev_hash != prev or entry_hash(ts, kind, employer, json.loads(body), prev) != h:
                return False, seq
            prev = h
            n, last = n + 1, seq
        if count and (n < count or (n == count and prev != head)):
            return False, last + 1                      # entries are missing from the end
        return True, None

    def entries(self, employer: str | None = None):
        q = "SELECT seq,kind,employer,body FROM log"
        args: tuple = ()
        if employer:
            q += " WHERE employer=?"
            args = (employer,)
        return [(s, k, e, json.loads(b)) for s, k, e, b in self.db.execute(q + " ORDER BY seq", args)]

    # --- intents ---------------------------------------------------------
    def new_intent(self, employer: str, contractor: str, period: str, batch_key: str,
                   currency: str, amount: int) -> str:
        request_id = str(uuid.uuid4())
        self.db.execute("INSERT INTO intents VALUES(?,?,?,?,?,?,?,?)",
                        (request_id, employer, contractor, period, batch_key, currency, amount, "INTENT"))
        self.db.commit()
        self.log("intent", employer, request_id=request_id, contractor=contractor,
                 currency=currency, amount=amount)
        return request_id

    def set_state(self, request_id: str, state: str, **extra) -> None:
        self.db.execute("UPDATE intents SET state=? WHERE request_id=?", (state, request_id))
        self.db.commit()
        row = self.db.execute("SELECT employer FROM intents WHERE request_id=?", (request_id,)).fetchone()
        self.log("outcome", row[0], request_id=request_id, state=state, **extra)

    def live_contractors(self, employer: str, period: str) -> set[str]:
        rows = self.db.execute("""SELECT contractor FROM intents WHERE employer=? AND period=?
                                  AND state IN ('INTENT','SENT','PROCESSING','PAID','UNKNOWN')""",
                               (employer, period))
        return {r[0] for r in rows}

    def unresolved(self) -> list[tuple[str, str]]:
        return list(self.db.execute("SELECT request_id, employer FROM intents WHERE state IN ('INTENT','UNKNOWN')"))

    # --- batches ---------------------------------------------------------
    def executed_batches(self) -> set[str]:
        return {r[0] for r in self.db.execute("SELECT batch_key FROM batches")}

    def mark_batch(self, batch_key: str, employer: str) -> None:
        self.db.execute("INSERT OR IGNORE INTO batches VALUES(?,?)", (batch_key, employer))
        self.db.commit()
