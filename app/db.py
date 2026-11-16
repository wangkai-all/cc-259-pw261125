"""SQLite persistence for the shared-analytics authorization simulation.

Tables are intentionally split into three concerns:

* business data       -> metrics, segments
* authorization data  -> grant_versions, grant_cols, grant_rows
* delivery machinery  -> queries, query_plans, cache_entries, deliveries,
                         download_jobs

The business table has a *stable* row_key.  Pagination cursors, cache
keys and download rows all point at row_key, so an authorization change
can never silently shift a row to a different page.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import date, timedelta
from pathlib import Path

DB_PATH = Path(os.environ.get("SHAN_DATA", Path(__file__).resolve().parent.parent / "data")) / "analytics.sqlite3"

_lock = threading.RLock()
_thread_local = threading.local()

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS segments (
    segment      TEXT PRIMARY KEY,
    label        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
    row_key        TEXT PRIMARY KEY,
    segment        TEXT NOT NULL REFERENCES segments(segment),
    organization   TEXT NOT NULL,
    occurred_at    TEXT NOT NULL,
    revenue_cents  INTEGER NOT NULL,
    orders         INTEGER NOT NULL,
    refund_cents   INTEGER NOT NULL,
    active_users   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_segment ON metrics(segment, occurred_at, row_key);

-- current grants kept normalised; the page reads them to build versions
CREATE TABLE IF NOT EXISTS grant_versions (
    version       INTEGER PRIMARY KEY AUTOINCREMENT,
    principal_id  TEXT NOT NULL,
    status        TEXT NOT NULL,             -- active | revoked
    created_at    REAL NOT NULL,
    created_by    TEXT NOT NULL,
    note          TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS grant_cols (
    version    INTEGER NOT NULL REFERENCES grant_versions(version),
    column_name TEXT NOT NULL,
    PRIMARY KEY (version, column_name)
);

CREATE TABLE IF NOT EXISTS grant_rows (
    version    INTEGER NOT NULL REFERENCES grant_versions(version),
    organization TEXT NOT NULL,
    PRIMARY KEY (version, organization)
);

-- each published grant state is what a query can pin
CREATE TABLE IF NOT EXISTS grant_snapshots (
    snapshot_id   TEXT PRIMARY KEY,
    version       INTEGER NOT NULL REFERENCES grant_versions(version),
    principal_id  TEXT NOT NULL,
    captured_at   REAL NOT NULL,
    cols_json     TEXT NOT NULL,
    orgs_json     TEXT NOT NULL,
    digest        TEXT NOT NULL,
    data_epoch    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS principals (
    principal_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    team         TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'analyst'  -- analyst | admin
);

CREATE TABLE IF NOT EXISTS queries (
    query_id      TEXT PRIMARY KEY,
    principal_id  TEXT NOT NULL,
    sql           TEXT NOT NULL,
    spec_json     TEXT NOT NULL,
    requested_cols_json TEXT NOT NULL,
    requested_orgs_json TEXT NOT NULL,
    status        TEXT NOT NULL,             -- queued|running|succeeded|failed|denied
    auth_mode     TEXT NOT NULL,             -- pinned | recheck
    auth_snapshot TEXT,                      -- snapshot id captured at launch
    auth_version  INTEGER,
    version_digest TEXT,
    data_epoch    INTEGER NOT NULL DEFAULT 1,
    created_at    REAL NOT NULL,
    started_at    REAL,
    finished_at   REAL,
    row_count     INTEGER,
    error         TEXT,
    cache_entry   TEXT,
    plan_json     TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS query_results (
    query_id  TEXT PRIMARY KEY REFERENCES queries(query_id),
    rows_json TEXT NOT NULL
);

-- internal scope-filtered detail rows; never delivered wholesale.  Used to
-- safely recompute a narrower aggregate after a revocation.
CREATE TABLE IF NOT EXISTS query_detail (
    query_id  TEXT PRIMARY KEY REFERENCES queries(query_id),
    rows_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cache_entries (
    cache_entry_id TEXT PRIMARY KEY,
    created_by     TEXT NOT NULL,
    sql            TEXT NOT NULL,
    key_json       TEXT NOT NULL,            -- logical cache key incl. scope + version digest
    key_digest     TEXT NOT NULL UNIQUE,
    auth_snapshot  TEXT,                     -- snapshot under which payload was computed
    auth_version   INTEGER,
    version_digest TEXT NOT NULL,
    scope_cols_json TEXT NOT NULL,
    scope_orgs_json TEXT NOT NULL,
    data_epoch     INTEGER NOT NULL,
    created_at     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS cache_payloads (
    cache_entry_id TEXT PRIMARY KEY REFERENCES cache_entries(cache_entry_id),
    rows_json      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS page_deliveries (
    page_id       TEXT PRIMARY KEY,
    query_id      TEXT NOT NULL REFERENCES queries(query_id),
    cursor_id     TEXT NOT NULL,
    page_index    INTEGER NOT NULL,
    principal_id  TEXT NOT NULL,
    policy        TEXT NOT NULL,
    auth_snapshot TEXT,
    auth_version  INTEGER,
    served_cols_json TEXT NOT NULL,
    served_orgs_json TEXT NOT NULL,
    withheld_cols_json TEXT NOT NULL DEFAULT '[]',
    withheld_orgs_json TEXT NOT NULL DEFAULT '[]',
    rows_json     TEXT NOT NULL,             -- frozen bytes handed to the client
    row_count     INTEGER NOT NULL,
    reshaped      INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    UNIQUE(query_id, page_index, principal_id)
);

CREATE TABLE IF NOT EXISTS delivery_cursors (
    cursor_id    TEXT PRIMARY KEY,
    query_id     TEXT NOT NULL REFERENCES queries(query_id),
    principal_id TEXT NOT NULL,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS denials (
    denial_id  TEXT PRIMARY KEY,
    at         REAL NOT NULL,
    principal_id TEXT NOT NULL,
    kind       TEXT NOT NULL,               -- launch|page|cache|download|plan
    query_id   TEXT,
    job_id     TEXT,
    code       TEXT NOT NULL,
    reason     TEXT NOT NULL,
    detail_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS download_jobs (
    job_id        TEXT PRIMARY KEY,
    query_id      TEXT NOT NULL REFERENCES queries(query_id),
    principal_id  TEXT NOT NULL,
    status        TEXT NOT NULL,             -- pending | running | paused | revoked | completed
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL,
    auth_snapshot TEXT,
    auth_version  INTEGER,
    chunks_total  INTEGER NOT NULL,
    chunks_done   INTEGER NOT NULL DEFAULT 0,
    rows_total    INTEGER NOT NULL,
    rows_done     INTEGER NOT NULL DEFAULT 0,
    rows_per_chunk INTEGER NOT NULL,
    note          TEXT,
    last_denial   TEXT
);

CREATE TABLE IF NOT EXISTS download_chunks (
    job_id      TEXT NOT NULL REFERENCES download_jobs(job_id),
    chunk_index INTEGER NOT NULL,
    rows_json   TEXT NOT NULL,
    PRIMARY KEY (job_id, chunk_index)
);

-- identities actually delivered by each download job, so a scope change
-- between chunks cannot cause a row to be skipped or repeated
CREATE TABLE IF NOT EXISTS download_delivered (
    job_id     TEXT NOT NULL REFERENCES download_jobs(job_id),
    identity   TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    PRIMARY KEY (job_id, identity)
);


CREATE TABLE IF NOT EXISTS audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    at         REAL NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    subject    TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS system_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Columns the demo can expose.  These map 1:1 to metrics columns.
BIZ_COLUMNS = {
    "row_key": "TEXT",
    "segment": "TEXT",
    "organization": "TEXT",
    "occurred_at": "TEXT",
    "revenue_cents": "INTEGER",
    "orders": "INTEGER",
    "refund_cents": "INTEGER",
    "active_users": "INTEGER",
}

# Which raw fact column backs each deliverable measure.
MEASURE_SOURCE = {
    "revenue_cents": "revenue_cents",
    "orders": "orders",
    "refund_cents": "refund_cents",
    "active_users": "active_users",
}

SAMPLE_ORGS = {
    "north": ("Northwind Labs", "north-america"),
    "south": ("Southern Cross", "apac"),
    "east": ("Eastbridge", "emea"),
    "west": ("Westweld", "americas"),
}


def connect() -> sqlite3.Connection:
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        # Autocommit mode: each statement commits immediately.  This keeps a
        # simulated slow query from holding a write lock while it sleeps, so
        # a grant revocation can land *during* the slow window -- which is
        # exactly the race this simulation is about.
        conn = sqlite3.connect(
            DB_PATH, timeout=30, check_same_thread=False, isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        _thread_local.conn = conn
    return conn


RESET_TABLES = [
    "download_delivered", "download_chunks", "download_jobs", "denials",
    "delivery_cursors", "page_deliveries", "cache_payloads", "cache_entries",
    "query_detail", "query_results", "queries", "grant_snapshots",
    "grant_rows", "grant_cols", "grant_versions", "audit", "metrics",
    "segments", "principals", "system_state",
]


def reset_data(conn: sqlite3.Connection) -> None:
    """Clear all rows but keep the schema -- much faster than re-creating it,
    and keeps per-thread connections valid."""
    for name in RESET_TABLES:
        try:
            conn.execute(f'DELETE FROM "{name}"')
        except sqlite3.OperationalError:
            pass
    conn.execute("INSERT OR REPLACE INTO sqlite_sequence(name,seq) "
                 "SELECT name,0 FROM sqlite_sequence")
    seed(conn)


def init(force: bool = False) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        conn = connect()
        conn.executescript(SCHEMA)
        if force:
            reset_data(conn)
        elif conn.execute("SELECT COUNT(*) c FROM principals").fetchone()["c"] == 0:
            seed(conn)


def seed(conn: sqlite3.Connection) -> None:
    now = time.time()
    # Seed inside one transaction: the connection is autocommit, and 1,600
    # individual fsyncs is the dominant cost on slow filesystems.
    conn.execute("BEGIN")
    try:
        _seed_rows(conn, now)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _seed_rows(conn: sqlite3.Connection, now: float) -> None:
    principal_rows = [
        ("analyst-ada", "Ada Lovelace", "Revenue Analytics", "analyst"),
        ("analyst-bo", "Bo Chen", "Revenue Analytics", "analyst"),
        ("analyst-cy", "Cy Okafor", "Platform Ops", "analyst"),
        ("admin-root", "Root Admin", "Security", "admin"),
    ]
    conn.executemany("INSERT INTO principals VALUES (?,?,?,?)", principal_rows)

    for org, (label, team) in SAMPLE_ORGS.items():
        conn.execute(
            "INSERT INTO segments VALUES (?,?)",
            (org, f"{label} ({team})"),
        )

    # deterministic synthetic fact table: 400 rows per org, 1,600 total
    start = date(2026, 1, 1)
    rows = []
    for org_index, (org, _) in enumerate(SAMPLE_ORGS.items()):
        for i in range(400):
            d = start + timedelta(days=(i * 3 + org_index) % 300)
            rows.append(
                (
                    f"{org}-{i:04d}",
                    org,
                    org,
                    d.isoformat(),
                    4200 + ((i * 977 + org_index * 31) % 580000),
                    1 + ((i * 7 + org_index) % 24),
                    (i * 53) % 9000 if i % 5 else 0,
                    1 + ((i * 11 + org_index * 3) % 90),
                )
            )
    conn.executemany(
        "INSERT INTO metrics VALUES (?,?,?,?,?,?,?,?)",
        rows,
    )

    # initial grants: Ada gets revenue/orders for north + south + east;
    # Bo gets revenue/refunds for north + south; Cy gets everything except
    # organization 'west' (west rows must never leak).
    dims = ["organization", "segment", "occurred_at"]
    _insert_grant(conn, "analyst-ada", dims + ["revenue_cents", "orders"], ["north", "south", "east"], "system", "initial")
    _insert_grant(conn, "analyst-bo", dims + ["revenue_cents", "refund_cents"], ["north", "south"], "system", "initial")
    _insert_grant(conn, "analyst-cy", dims + ["revenue_cents", "orders", "refund_cents", "active_users"], ["north", "south", "east"], "system", "initial")
    _insert_grant(conn, "admin-root", dims + ["revenue_cents", "orders", "refund_cents", "active_users"], list(SAMPLE_ORGS), "system", "initial admin")

    conn.execute("INSERT OR REPLACE INTO system_state VALUES ('epoch', '1')")
    conn.execute("INSERT OR REPLACE INTO system_state VALUES ('clock_offset', '0')")
    conn.execute("INSERT OR REPLACE INTO system_state VALUES ('publish_seq', '1')")


def _insert_grant(
    conn: sqlite3.Connection,
    principal: str,
    cols: list[str],
    orgs: list[str],
    actor: str,
    note: str,
) -> int:
    cur = conn.execute(
        "INSERT INTO grant_versions(principal_id,status,created_at,created_by,note) VALUES (?,?,?,?,?)",
        (principal, "active", time.time(), actor, note),
    )
    version = cur.lastrowid
    conn.executemany(
        "INSERT INTO grant_cols VALUES (?,?)", [(version, c) for c in cols]
    )
    conn.executemany(
        "INSERT INTO grant_rows VALUES (?,?)", [(version, o) for o in orgs]
    )
    return version


def bump_epoch(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT value FROM system_state WHERE key='epoch'").fetchone()
    epoch = int(row["value"]) if row else 1
    epoch += 1
    conn.execute("INSERT OR REPLACE INTO system_state VALUES ('epoch', ?)", (str(epoch),))
    return epoch


def audit(conn: sqlite3.Connection, actor: str, action: str, subject: str, detail: dict | None = None, at: float | None = None) -> None:
    import json

    conn.execute(
        "INSERT INTO audit(at,actor,action,subject,detail_json) VALUES (?,?,?,?,?)",
        (at or time.time(), actor, action, subject, json.dumps(detail or {})),
    )
