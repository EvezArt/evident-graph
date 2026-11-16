#!/usr/bin/env python3
"""EVIDENT institutional-failure graph — schema + append-only chain.

Five tables, append-only: requests, breaches, escalations, outcomes, cross_references.
Nothing is ever UPDATEd or DELETEd — SQLite triggers enforce it. Every INSERT is
hash-chained (prev_hash -> record_hash) exactly like the witness ledger, so the
graph is citable: any retroactive edit breaks the chain and verify.py detects it.

Build:  python3 build_graph.py
Verify: python3 verify_graph.py
"""
import hashlib
import json
import os
import pathlib
import sqlite3
import time

HERE = pathlib.Path(__file__).parent
DB = HERE / 'graph.db'
LEDGER = pathlib.Path('/opt/data/evident/ledger.jsonl')

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- 1. REQUESTS ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS requests (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id          TEXT UNIQUE NOT NULL,
  agency             TEXT NOT NULL,
  jurisdiction        TEXT NOT NULL,
  statute             TEXT,
  date_submitted      TEXT,
  delivery_method     TEXT,
  records_sought      TEXT,
  response_deadline   TEXT,
  actual_response_date TEXT,
  days_overdue        INTEGER,
  request_doc_hash    TEXT,
  notes               TEXT,
  created_at          TEXT NOT NULL
);

-- 2. BREACHES ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS breaches (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  agency            TEXT NOT NULL,
  statute_section   TEXT,
  breach_type       TEXT NOT NULL,   -- missed_deadline | no_extension_notice | no_privilege_log | incomplete_production | other
  date_detected     TEXT,
  date_logged       TEXT,
  severity          INTEGER,         -- 1 (admin) .. 5 (rights-defeating)
  description       TEXT,
  request_id        TEXT REFERENCES requests(request_id),
  evidence_doc_id   TEXT,
  created_at        TEXT NOT NULL
);

-- 3. ESCALATIONS ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS escalations (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  target            TEXT NOT NULL,
  instrument_type   TEXT NOT NULL,   -- petition | mandamus | creditor_objection | ombudsman_complaint | court_filing | federal_docket | agency_objection | tip_submission
  reference_number  TEXT,
  date_filed        TEXT,
  status            TEXT,
  opposing_response TEXT,
  cost              REAL,
  request_id        TEXT REFERENCES requests(request_id),
  created_at        TEXT NOT NULL
);

-- 4. OUTCOMES ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outcomes (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id        TEXT REFERENCES requests(request_id),
  outcome_type      TEXT NOT NULL,   -- full_production | partial_production | denial | settled | court_ruled | no_response | other
  outcome_date      TEXT,
  description       TEXT,
  linked_breach_id  INTEGER REFERENCES breaches(id),
  created_at        TEXT NOT NULL
);

-- 5. CROSS-REFERENCES -------------------------------------------------------
CREATE TABLE IF NOT EXISTS cross_references (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  from_table  TEXT NOT NULL,
  from_id     INTEGER NOT NULL,
  to_table    TEXT NOT NULL,
  to_id       INTEGER NOT NULL,
  relation    TEXT,
  note        TEXT,
  created_at  TEXT NOT NULL
);

-- append-only audit chain ---------------------------------------------------
CREATE TABLE IF NOT EXISTS chain (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  table_name TEXT NOT NULL,
  row_id     INTEGER NOT NULL,
  op         TEXT NOT NULL CHECK (op = 'INSERT'),
  row_hash   TEXT NOT NULL,
  prev_hash  TEXT NOT NULL,
  record_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- documents under witness (the 171-record ledger) ---------------------------
CREATE TABLE IF NOT EXISTS documents (
  seq           INTEGER PRIMARY KEY,
  doc_id        TEXT UNIQUE NOT NULL,
  title         TEXT,
  source_url    TEXT,
  sha256        TEXT NOT NULL,
  bytes         INTEGER,
  witnessed_at  TEXT,
  record_hash   TEXT
);

-- enforce append-only --------------------------------------------------------
CREATE TRIGGER IF NOT EXISTS no_update_requests  BEFORE UPDATE ON requests  BEGIN SELECT RAISE(ABORT,'append-only: requests'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_requests  BEFORE DELETE ON requests  BEGIN SELECT RAISE(ABORT,'append-only: requests'); END;
CREATE TRIGGER IF NOT EXISTS no_update_breaches  BEFORE UPDATE ON breaches  BEGIN SELECT RAISE(ABORT,'append-only: breaches'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_breaches  BEFORE DELETE ON breaches  BEGIN SELECT RAISE(ABORT,'append-only: breaches'); END;
CREATE TRIGGER IF NOT EXISTS no_update_escalations BEFORE UPDATE ON escalations BEGIN SELECT RAISE(ABORT,'append-only: escalations'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_escalations BEFORE DELETE ON escalations BEGIN SELECT RAISE(ABORT,'append-only: escalations'); END;
CREATE TRIGGER IF NOT EXISTS no_update_outcomes BEFORE UPDATE ON outcomes BEGIN SELECT RAISE(ABORT,'append-only: outcomes'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_outcomes BEFORE DELETE ON outcomes BEGIN SELECT RAISE(ABORT,'append-only: outcomes'); END;
CREATE TRIGGER IF NOT EXISTS no_update_xref BEFORE UPDATE ON cross_references BEGIN SELECT RAISE(ABORT,'append-only: cross_references'); END;
CREATE TRIGGER IF NOT EXISTS no_delete_xref BEFORE DELETE ON cross_references BEGIN SELECT RAISE(ABORT,'append-only: cross_references'); END;
"""

GENESIS = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class Graph:
    def __init__(self, path=DB):
        self.con = sqlite3.connect(path)
        self.con.row_factory = sqlite3.Row
        self.con.executescript(SCHEMA)
        self.tables = ['requests', 'breaches', 'escalations', 'outcomes', 'cross_references']

    def _prev(self):
        r = self.con.execute("SELECT record_hash FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
        return r['record_hash'] if r else GENESIS

    def insert(self, table, row):
        cols = list(row.keys())
        sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        cur = self.con.execute(sql, [row[c] for c in cols])
        row_id = cur.lastrowid
        stored = dict(self.con.execute(f"SELECT * FROM {table} WHERE id=?", (row_id,)).fetchone())
        body = {k: v for k, v in stored.items() if k != 'id'}
        row_hash = hashlib.sha256(canonical(body).encode()).hexdigest()
        prev = self._prev()
        rec_hash = hashlib.sha256((prev + canonical({'t': table, 'r': row_id, 'h': row_hash})).encode()).hexdigest()
        self.con.execute(
            "INSERT INTO chain (table_name,row_id,op,row_hash,prev_hash,record_hash,created_at) VALUES (?,?,?,?,?,?,?)",
            (table, row_id, 'INSERT', row_hash, prev, rec_hash, now()))
        self.con.commit()
        return row_id

    def load_ledger(self):
        latest = {}
        for line in LEDGER.read_text().splitlines():
            if not line.strip():
                continue
            x = json.loads(line)
            latest[x['doc_id']] = x          # keep the most recent witnessing
        for x in latest.values():
            self.con.execute(
                "INSERT OR IGNORE INTO documents (seq,doc_id,title,source_url,sha256,bytes,witnessed_at,record_hash)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (x['seq'], x['doc_id'], x['title'], x['source_url'], x['sha256'], x['bytes'],
                 x['witnessed_at'], x['record_hash']))
        self.con.commit()
        return len(latest)


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
