"""Versioned, column- and row-scoped authorization for the shared analytics repo.

Design decisions encoded here (also surfaced in the UI's "policy" panel):

1. A query captures a **snapshot** of its principal's grant at launch.  The
   snapshot is immutable.  Every *execution* decision (which columns/rows the
   SQL may touch, which cache entries are usable) is made against that
   snapshot, not against the live grant.

2. Every *delivery* (a page of results, a download chunk, a cached aggregate
   response) re-checks the live grant.  Delivered bytes are immutable and
   never recalled; anything not yet delivered is filtered against the live
   grant at the moment it would be handed over.

3. Cache entries are keyed by (SQL, snapshot digest, data epoch).  Reusing a
   cache entry is allowed only when the cached key digest matches AND the
   live grant still covers every column/organization present in the cached
   payload.  A cache entry computed under a wider grant is therefore never
   served to a narrower one, and it is not deleted when one principal loses
   access -- other principals may still use it.

4. Pagination cursors bind (query, principal, frozen delivered page set).  A
   cursor from another principal is denied.  A cursor whose query pinned a
   wider grant is served *reshaped*: already-delivered rows stay exactly as
   delivered (immutable), not-yet-delivered rows are filtered by the live
   grant.  If nothing new remains the page returns an explicit "nothing left
   to deliver" result rather than silently skipping rows.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time

from . import db


class Denied(Exception):
    def __init__(self, code: str, reason: str, detail: dict | None = None):
        super().__init__(reason)
        self.code = code
        self.reason = reason
        self.detail = detail or {}


# ---------------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------------


def _grant_for_version(conn, version: int) -> dict:
    cols = [
        r["column_name"]
        for r in conn.execute(
            "SELECT column_name FROM grant_cols WHERE version=? ORDER BY column_name",
            (version,),
        )
    ]
    orgs = [
        r["organization"]
        for r in conn.execute(
            "SELECT organization FROM grant_rows WHERE version=? ORDER BY organization",
            (version,),
        )
    ]
    return {"columns": cols, "organizations": orgs}


def digest_of(cols, orgs) -> str:
    payload = json.dumps(
        {"columns": sorted(cols), "organizations": sorted(orgs)}, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def live_grant(conn, principal_id: str) -> dict:
    """Current effective grant + the version it came from."""
    row = conn.execute(
        "SELECT * FROM grant_versions WHERE principal_id=? AND status='active' "
        "ORDER BY version DESC LIMIT 1",
        (principal_id,),
    ).fetchone()
    if row is None:
        return {
            "version": None,
            "digest": digest_of([], []),
            "columns": [],
            "organizations": [],
            "note": "no active grant",
            "granted_at": None,
        }
    g = _grant_for_version(conn, row["version"])
    return {
        "version": row["version"],
        "digest": digest_of(g["columns"], g["organizations"]),
        "columns": g["columns"],
        "organizations": g["organizations"],
        "note": row["note"],
        "granted_at": row["created_at"],
    }


def publish_grant(
    conn,
    principal_id: str,
    columns: list[str],
    organizations: list[str],
    actor: str,
    note: str = "",
) -> dict:
    columns = sorted(set(columns))
    organizations = sorted(set(organizations))
    unknown_cols = [c for c in columns if c not in db.BIZ_COLUMNS]
    unknown_orgs = [o for o in organizations if o not in db.SAMPLE_ORGS]
    if unknown_cols or unknown_orgs:
        raise Denied(
            "invalid_grant",
            "grant references unknown columns or organizations",
            {"columns": unknown_cols, "organizations": unknown_orgs},
        )
    version = db._insert_grant(conn, principal_id, columns, organizations, actor, note)
    digest = digest_of(columns, organizations)
    conn.execute(
        "INSERT INTO grant_snapshots(snapshot_id,version,principal_id,captured_at,"
        "cols_json,orgs_json,digest,data_epoch) VALUES (?,?,?,?,?,?,?,?)",
        (
            f"snap-v{version}",
            version,
            principal_id,
            time.time(),
            json.dumps(columns),
            json.dumps(organizations),
            digest,
            1,
        ),
    )
    # Note: publishing a grant does *not* bump the data epoch.  Cache
    # validity is decided by scope (columns + organizations), so an
    # unaffected principal keeps using shared entries; an affected one
    # naturally derives a different cache key.
    db.audit(
        conn,
        actor,
        "grant.publish",
        principal_id,
        {"version": version, "columns": columns, "organizations": organizations,
         "digest": digest, "note": note},
    )
    return {"version": version, "digest": digest}


def snapshot_for_query(conn, principal_id: str, mode: str) -> dict:
    """Capture (pinned) or re-resolve (recheck) the authorization context."""
    if mode == "pinned":
        g = live_grant(conn, principal_id)
        snap_id = f"snap-q-{secrets.token_hex(5)}"
        conn.execute(
            "INSERT INTO grant_snapshots(snapshot_id,version,principal_id,captured_at,"
            "cols_json,orgs_json,digest,data_epoch) VALUES (?,?,?,?,?,?,?,?)",
            (
                snap_id,
                g["version"] or 0,
                principal_id,
                time.time(),
                json.dumps(g["columns"]),
                json.dumps(g["organizations"]),
                g["digest"],
                data_epoch(conn),
            ),
        )
        return {
            "snapshot": snap_id,
            "version": g["version"],
            "digest": g["digest"],
            "columns": g["columns"],
            "organizations": g["organizations"],
            "mode": "pinned",
        }
    g = live_grant(conn, principal_id)
    # recheck still records the launch-time grant as an immutable snapshot so
    # execution can intersect it with the live grant (narrowest wins).  The
    # snapshot id is what makes "revoked after launch but before execution"
    # observable and auditable.
    snap_id = f"snap-q-{secrets.token_hex(5)}"
    conn.execute(
        "INSERT INTO grant_snapshots(snapshot_id,version,principal_id,captured_at,"
        "cols_json,orgs_json,digest,data_epoch) VALUES (?,?,?,?,?,?,?,?)",
        (
            snap_id,
            g["version"] or 0,
            principal_id,
            time.time(),
            json.dumps(g["columns"]),
            json.dumps(g["organizations"]),
            g["digest"],
            data_epoch(conn),
        ),
    )
    return {
        "snapshot": snap_id,
        "version": g["version"],
        "digest": g["digest"],
        "columns": g["columns"],
        "organizations": g["organizations"],
        "mode": "recheck",
    }


def load_snapshot(conn, snapshot_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM grant_snapshots WHERE snapshot_id=?", (snapshot_id,)
    ).fetchone()
    if row is None:
        return None
    return {
        "snapshot": row["snapshot_id"],
        "version": row["version"],
        "digest": row["digest"],
        "columns": json.loads(row["cols_json"]),
        "organizations": json.loads(row["orgs_json"]),
        "captured_at": row["captured_at"],
        "data_epoch": row["data_epoch"],
    }


def data_epoch(conn) -> int:
    row = conn.execute("SELECT value FROM system_state WHERE key='epoch'").fetchone()
    return int(row["value"]) if row else 1



def record_denial(
    conn,
    principal_id: str,
    kind: str,
    code: str,
    reason: str,
    detail: dict,
    query_id: str | None = None,
    job_id: str | None = None,
) -> str:
    denial_id = f"den-{secrets.token_hex(6)}"
    conn.execute(
        "INSERT INTO denials(denial_id,at,principal_id,kind,query_id,job_id,code,reason,detail_json)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (
            denial_id,
            time.time(),
            principal_id,
            kind,
            query_id,
            job_id,
            code,
            reason,
            json.dumps(detail),
        ),
    )
    db.audit(
        conn,
        principal_id,
        "access.denied",
        query_id or job_id or kind,
        {"code": code, "reason": reason, **detail},
    )
    return denial_id


# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------


def intersect_columns(grant_cols: list[str], requested: list[str]) -> tuple[list[str], list[str]]:
    """Return (served, withheld).  withheld = requested but not granted."""
    requested = sorted(set(requested))
    served = [c for c in requested if c in set(grant_cols)]
    withheld = [c for c in requested if c not in set(grant_cols)]
    return served, withheld


def intersect_orgs(grant_orgs: list[str], requested: list[str]) -> tuple[list[str], list[str]]:
    requested = sorted(set(requested))
    if not requested:
        # no explicit organization filter means "all granted orgs"
        return sorted(set(grant_orgs)), []
    served = [o for o in requested if o in set(grant_orgs)]
    withheld = [o for o in requested if o not in set(grant_orgs)]
    return served, withheld


def build_where(orgs: list[str], filters: dict | None = None) -> tuple[str, list]:
    """SQL predicate for row scope.  Empty orgs means deny-all, never all."""
    if not orgs:
        return "0", []
    placeholders = ",".join("?" for _ in orgs)
    sql = f"m.organization IN ({placeholders})"
    params: list = list(orgs)
    filters = filters or {}
    if filters.get("segment"):
        allowed = [s for s in filters["segment"] if s in orgs]
        if not allowed:
            return "0", []
        ph = ",".join("?" for _ in allowed)
        sql += f" AND m.segment IN ({ph})"
        params.extend(allowed)
    if filters.get("date_from"):
        sql += " AND m.occurred_at >= ?"
        params.append(filters["date_from"])
    if filters.get("date_to"):
        sql += " AND m.occurred_at <= ?"
        params.append(filters["date_to"])
    return sql, params
