#!/usr/bin/env python3
"""Independent verifier for the EVIDENT graph.

Recomputes every chain hash from the stored rows and checks:
  1. the append-only chain (prev_hash -> record_hash) is intact;
  2. no row was UPDATEd or DELETEd (triggers enforce it; this double-checks);
  3. every foreign key resolves;
  4. the documents table still matches the witness ledger byte-for-byte;
  5. nothing is missing from the ledger.

Exit code 0 = intact. Any failure prints the offending record and exits 1.
"""
import hashlib
import json
import pathlib
import sqlite3
import sys

HERE = pathlib.Path(__file__).parent
DB = HERE / 'graph.db'
LEDGER = pathlib.Path('/opt/data/evident/ledger.jsonl')
GENESIS = "0" * 64


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def main():
    if not DB.exists():
        print('FAIL: graph.db missing')
        return 1
    con = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
    con.row_factory = sqlite3.Row
    fails = []

    # 1 + 2: chain integrity and row hashes
    prev = GENESIS
    rows = con.execute("SELECT * FROM chain ORDER BY seq").fetchall()
    for r in rows:
        table, row_id = r['table_name'], r['row_id']
        stored = con.execute(f"SELECT * FROM {table} WHERE id=?", (row_id,)).fetchone()
        if stored is None:
            fails.append(f"chain seq {r['seq']}: {table}.{row_id} missing")
            continue
        body = {k: v for k, v in dict(stored).items() if k != 'id'}
        row_hash = hashlib.sha256(canonical(body).encode()).hexdigest()
        if row_hash != r['row_hash']:
            fails.append(f"chain seq {r['seq']}: row_hash mismatch on {table}.{row_id}")
        if r['prev_hash'] != prev:
            fails.append(f"chain seq {r['seq']}: prev_hash break")
        rec = hashlib.sha256((prev + canonical({'t': table, 'r': row_id, 'h': row_hash})).encode()).hexdigest()
        if rec != r['record_hash']:
            fails.append(f"chain seq {r['seq']}: record_hash mismatch")
        if r['op'] != 'INSERT':
            fails.append(f"chain seq {r['seq']}: non-INSERT op {r['op']}")
        prev = r['record_hash']
    print(f"chain: {len(rows)} records checked")

    # 3: foreign keys
    for table, col, ref in [('breaches', 'request_id', 'requests'),
                            ('escalations', 'request_id', 'requests'),
                            ('outcomes', 'request_id', 'requests')]:
        bad = con.execute(
            f"SELECT COUNT(*) FROM {table} t WHERE t.{col} IS NOT NULL "
            f"AND NOT EXISTS (SELECT 1 FROM {ref} r WHERE r.request_id = t.{col})").fetchone()[0]
        if bad:
            fails.append(f"{table}.{col}: {bad} unresolved foreign keys")
    print("foreign keys: checked")

    # 4 + 5: documents vs ledger
    ledger = {}
    for line in LEDGER.read_text().splitlines():
        if line.strip():
            x = json.loads(line)
            ledger[x['doc_id']] = x
    docs = {d['doc_id']: dict(d) for d in con.execute("SELECT * FROM documents")}
    missing = [k for k in ledger if k not in docs]
    extra = [k for k in docs if k not in ledger]
    mismatch = [k for k in ledger if k in docs and (
        ledger[k]['sha256'] != docs[k]['sha256'] or ledger[k]['record_hash'] != docs[k]['record_hash'])]
    if missing:
        fails.append(f"documents: {len(missing)} ledger docs missing from graph")
    if extra:
        fails.append(f"documents: {len(extra)} graph docs not in ledger")
    if mismatch:
        fails.append(f"documents: {len(mismatch)} hash mismatches")
    print(f"documents: {len(docs)} in graph, {len(ledger)} in ledger")

    # 6: append-only triggers present
    trig = {r['name'] for r in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    need = {'no_update_requests', 'no_delete_requests', 'no_update_breaches', 'no_delete_breaches',
            'no_update_escalations', 'no_delete_escalations', 'no_update_outcomes', 'no_delete_outcomes',
            'no_update_xref', 'no_delete_xref'}
    if not need.issubset(trig):
        fails.append(f"triggers missing: {sorted(need - trig)}")
    print(f"triggers: {len(trig)} present")

    if fails:
        print('\nFAIL:')
        for f in fails[:20]:
            print('  -', f)
        return 1
    print('\nAll checks passed. Graph intact and citable.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
