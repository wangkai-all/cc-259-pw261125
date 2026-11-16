"""Query execution, cache lookup and result storage.

Authorization model implemented here (mirrored in the UI policy panel):

* At launch the principal's grant is captured as an immutable snapshot.
* Execution reads under the snapshot in ``pinned`` mode, or under
  ``live ∩ launch`` in ``recheck`` mode.  A revoked column/org can never be
  read after it has been revoked in recheck mode.
* The cache key is the tuple of *actually authorized* SQL shape
  (compiled SQL + served columns + served row scope + data epoch).  It is
  never keyed by principal, so equal-scope principals share entries and a
  revocation that narrows scope simply produces a different key.
* A cache hit stores the cached rows, but also (re)builds the internal
  detail rows so a later narrower delivery can be recomputed safely rather
  than serving an aggregate that includes revoked rows.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time

from . import authz, db

DIMENSIONS = ["organization", "segment", "occurred_at"]
MEASURES = ["revenue_cents", "orders", "refund_cents", "active_users"]
MAX_DELAY = 8.0


def _conn():
    return db.connect()


def now() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------


def compile_spec(spec: dict, served_cols: list[str], served_orgs: list[str]) -> tuple[str, list, list[str], list[str]]:
    """Compile only over *served* columns and organizations.

    Returns (sql, params, measures_served, group_by_served).  Anything not
    served is silently omitted from the compiled SQL, so execution cannot
    read a column the effective scope does not contain.
    """
    requested_measures = spec.get("measures") or []
    requested_groups = spec.get("group_by") or []
    measures = [m for m in requested_measures if m in MEASURES and m in served_cols]
    group_by = [g for g in requested_groups if g in DIMENSIONS and g in served_cols]
    if not measures:
        raise ValueError("no authorized measure remains to execute")

    parts = [f"m.{g}" for g in group_by]
    for m in measures:
        if m == "revenue_cents":
            parts.append("SUM(m.revenue_cents) AS revenue_cents")
        elif m == "refund_cents":
            parts.append("SUM(m.refund_cents) AS refund_cents")
        elif m == "orders":
            parts.append("COUNT(m.row_key) AS orders")
        elif m == "active_users":
            parts.append("MAX(m.active_users) AS active_users")

    filters = spec.get("filters") or {}
    where, params = authz.build_where(served_orgs, filters)
    sql = "SELECT " + ", ".join(parts) + " FROM metrics m WHERE " + where
    if group_by:
        sql += " GROUP BY " + ", ".join(f"m.{g}" for g in group_by)
        order = spec.get("order_by") or group_by[0]
        if order not in group_by:
            order = group_by[0]
        direction = "DESC" if spec.get("order_desc") else "ASC"
        sql += f" ORDER BY {order} {direction}"
    sql += " LIMIT 5000"
    return sql, params, measures, group_by


def _render(sql: str, params: list) -> str:
    out = sql
    for p in params:
        out = out.replace("?", f"'{str(p).replace(chr(39), chr(39) * 2)}'", 1)
    return out


def columns_from_sql(sql: str) -> list[str]:
    lowered = sql.lower()
    found = []
    for col in db.BIZ_COLUMNS:
        if re.search(rf"\b{re.escape(col)}\b", lowered):
            found.append(col)
    return sorted(found)


def sql_signature(sql: str) -> str:
    norm = re.sub(r"\s+", " ", sql.strip().lower())
    return hashlib.sha256(norm.encode()).hexdigest()[:16]


ORG_IN_RE = re.compile(r"(m|scoped)\.organization IN \([^)]*\)", re.I)


def sql_shape(sql: str) -> str:
    """SQL with row-scope literals abstracted out.

    The *column scope and organization set* are keyed separately, so the SQL
    shape must not embed them; otherwise two queries with the same shape but
    different scopes would never be recognized as near-miss cache candidates.
    """
    return ORG_IN_RE.sub(lambda m: f"{m.group(1)}.organization IN (...)", sql)


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------


def create_query(conn, principal_id: str, spec: dict, auth_mode: str, simulate_delay: float = 0.0, raw_sql: str | None = None) -> str:
    if auth_mode not in ("pinned", "recheck"):
        raise authz.Denied("bad_mode", "auth mode must be pinned or recheck")
    simulate_delay = max(0.0, min(float(simulate_delay or 0), MAX_DELAY))

    raw_sql = (raw_sql or "").strip() or None
    if raw_sql:
        if not re.match(r"(?is)^select\b", raw_sql):
            raise authz.Denied("bad_sql", "only SELECT statements are allowed")
        if ";" in raw_sql.rstrip(";"):
            raise authz.Denied("bad_sql", "multiple statements are not allowed")
        touched = columns_from_sql(raw_sql)
        if not touched:
            raise authz.Denied("bad_sql", "query references no known columns")
        requested_cols = touched
        requested_orgs = sorted(set(spec.get("organization") or []))
    else:
        requested_cols = sorted(
            set((spec.get("group_by") or []) + (spec.get("measures") or []) + ["organization"])
        )
        requested_orgs = sorted(set(spec.get("organization") or []))
        if not (spec.get("measures") or []):
            raise authz.Denied("bad_spec", "select at least one measure")
        for m in spec.get("measures") or []:
            if m not in MEASURES:
                raise authz.Denied("bad_spec", f"unknown measure {m}")
        for g in spec.get("group_by") or []:
            if g not in DIMENSIONS:
                raise authz.Denied("bad_spec", f"unknown dimension {g}")

    for c in requested_cols:
        if c not in db.BIZ_COLUMNS:
            raise authz.Denied("unknown_column", f"unknown column {c}")
    for o in requested_orgs:
        if o not in db.SAMPLE_ORGS:
            raise authz.Denied("unknown_org", f"unknown organization {o}")

    launch = authz.snapshot_for_query(conn, principal_id, auth_mode)
    served_cols, withheld_cols = authz.intersect_columns(launch["columns"], requested_cols)
    served_orgs, withheld_orgs = authz.intersect_orgs(launch["organizations"], requested_orgs)

    if raw_sql and withheld_cols:
        denial = authz.record_denial(
            conn, principal_id, "launch", "sql_scope_revoked",
            "free-form SQL references columns outside the grant; raw SQL cannot be rewritten safely",
            {"withheld_columns": withheld_cols, "requested_columns": requested_cols},
        )
        raise authz.Denied("sql_scope_revoked", "SQL references columns you cannot read: " + ", ".join(withheld_cols), {"denial_id": denial})

    if not served_cols or not served_orgs:
        denial = authz.record_denial(
            conn, principal_id, "launch", "no_overlap",
            "the requested scope does not overlap the current grant",
            {
                "requested_columns": requested_cols,
                "requested_organizations": requested_orgs,
                "grant_columns": launch["columns"],
                "grant_organizations": launch["organizations"],
                "withheld_columns": withheld_cols,
                "withheld_organizations": withheld_orgs,
            },
        )
        raise authz.Denied("no_overlap", "the requested scope does not overlap the current grant", {"denial_id": denial})

    plan = {
        "mode": auth_mode,
        "slow_query_seconds": simulate_delay,
        "authorization_at_launch": launch,
        "requested_columns": requested_cols,
        "requested_organizations": requested_orgs,
        "served_columns_at_launch": served_cols,
        "withheld_columns_at_launch": withheld_cols,
        "served_organizations_at_launch": served_orgs,
        "withheld_organizations_at_launch": withheld_orgs,
        "cache_lookup_key": None,
        "raw_sql": bool(raw_sql),
    }
    if raw_sql:
        if "organization" not in requested_cols:
            denial = authz.record_denial(
                conn, principal_id, "launch", "raw_sql_requires_organization",
                "free-form SQL must project the organization column so row scope can be enforced",
                {"requested_columns": requested_cols},
            )
            raise authz.Denied(
                "raw_sql_requires_organization",
                "free-form SQL must project the organization column so row scope can be enforced",
                {"denial_id": denial},
            )
        stored_sql = raw_sql
    else:
        try:
            stored_sql = _render(*compile_spec(spec, served_cols, served_orgs)[:2])
        except ValueError as exc:
            denial = authz.record_denial(
                conn, principal_id, "launch", "no_authorized_measure", str(exc),
                {"requested_columns": requested_cols, "served_columns": served_cols},
            )
            raise authz.Denied("no_authorized_measure", str(exc), {"denial_id": denial})

    query_id = f"q-{secrets.token_hex(6)}"
    conn.execute(
        "INSERT INTO queries(query_id,principal_id,sql,spec_json,requested_cols_json,"
        "requested_orgs_json,status,auth_mode,auth_snapshot,auth_version,version_digest,"
        "data_epoch,created_at,plan_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            query_id, principal_id, stored_sql,
            json.dumps(spec), json.dumps(requested_cols), json.dumps(requested_orgs),
            "queued", auth_mode, launch["snapshot"], launch["version"], launch["digest"],
            authz.data_epoch(conn), now(), json.dumps(plan),
        ),
    )
    db.audit(conn, principal_id, "query.launch", query_id, {
        "mode": auth_mode, "snapshot": launch["snapshot"], "version": launch["version"],
        "requested_columns": requested_cols, "requested_organizations": requested_orgs,
        "withheld_columns": withheld_cols, "withheld_organizations": withheld_orgs,
    })
    return query_id



def get_query(conn, query_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM queries WHERE query_id=?", (query_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Execution scope
# ---------------------------------------------------------------------------


def execution_scope(conn, query: dict) -> dict:
    """Effective read scope at execution time.

    pinned  -> launch snapshot (immutable, even if live grant was revoked)
    recheck -> launch snapshot ∩ live grant (narrowest wins)
    """
    launch = authz.load_snapshot(conn, query["auth_snapshot"]) if query.get("auth_snapshot") else None
    live = authz.live_grant(conn, query["principal_id"])
    if query["auth_mode"] == "pinned" and launch:
        cols, orgs = launch["columns"], launch["organizations"]
        source = "pinned_snapshot"
    elif launch:
        cols = sorted(set(launch["columns"]) & set(live["columns"]))
        orgs = sorted(set(launch["organizations"]) & set(live["organizations"]))
        source = "live_intersect_launch"
    else:
        cols, orgs = live["columns"], live["organizations"]
        source = "live"
    return {
        "columns": cols,
        "organizations": orgs,
        "source": source,
        "live_version": live["version"],
        "live_digest": live["digest"],
        "live_columns": live["columns"],
        "live_organizations": live["organizations"],
        "snapshot": launch["snapshot"] if launch else None,
        "snapshot_version": launch["version"] if launch else None,
    }


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def make_cache_key(sql: str, cols: list[str], orgs: list[str], epoch: int) -> dict:
    return {
        "sql_shape": sql_shape(sql),
        "columns": sorted(cols),
        "organizations": sorted(orgs),
        "data_epoch": epoch,
    }


def cache_key_digest(key: dict) -> str:
    return hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:24]


def find_cache(conn, key: dict) -> dict | None:
    cd = cache_key_digest(key)
    row = conn.execute("SELECT * FROM cache_entries WHERE key_digest=?", (cd,)).fetchone()
    if row is None:
        return None
    payload = conn.execute(
        "SELECT rows_json FROM cache_payloads WHERE cache_entry_id=?", (row["cache_entry_id"],)
    ).fetchone()
    if payload is None:
        return None
    return {"entry": dict(row), "rows": json.loads(payload["rows_json"])}


def cache_candidates(conn, key: dict) -> list[dict]:
    """Near-miss cache entries: same SQL shape but a different scope.

    Shown in the UI so an operator can see *why* a cache was not reused.
    Candidates are never served.
    """
    rows = conn.execute("SELECT * FROM cache_entries ORDER BY created_at DESC LIMIT 100").fetchall()
    out = []
    for r in rows:
        if sql_signature(sql_shape(r["sql"])) != sql_signature(key["sql_shape"]):
            continue
        cols = json.loads(r["scope_cols_json"])
        orgs = json.loads(r["scope_orgs_json"])
        same = cache_key_digest(key) == r["key_digest"]
        out.append({
            "cache_entry_id": r["cache_entry_id"],
            "key_digest": r["key_digest"],
            "columns": cols,
            "organizations": orgs,
            "created_by": r["created_by"],
            "auth_version": r["auth_version"],
            "is_exact": same,
            # differences relative to the caller's current key
            "extra_columns": [c for c in cols if c not in key["columns"]],
            "extra_organizations": [o for o in orgs if o not in key["organizations"]],
            "missing_columns": [c for c in key["columns"] if c not in cols],
            "missing_organizations": [o for o in key["organizations"] if o not in orgs],
        })
    return out


def explain(conn, sql: str, params: list) -> list[dict]:
    try:
        rows = conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
        return [dict(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        return [{"detail": f"plan unavailable: {exc}"}]


def store_cache(conn, query: dict, key: dict, cols: list[str], orgs: list[str], rows: list[dict]) -> str:
    cd = cache_key_digest(key)
    existing = conn.execute("SELECT cache_entry_id FROM cache_entries WHERE key_digest=?", (cd,)).fetchone()
    if existing:
        conn.execute("INSERT OR REPLACE INTO cache_payloads VALUES (?,?)", (existing["cache_entry_id"], json.dumps(rows)))
        db.audit(conn, query["principal_id"], "cache.refresh", existing["cache_entry_id"],
                 {"query_id": query["query_id"], "rows": len(rows)})
        return existing["cache_entry_id"]
    entry_id = f"c-{secrets.token_hex(5)}"
    conn.execute(
        "INSERT INTO cache_entries(cache_entry_id,created_by,sql,key_json,key_digest,"
        "auth_snapshot,auth_version,version_digest,scope_cols_json,scope_orgs_json,data_epoch,created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (entry_id, query["principal_id"], query["sql"], json.dumps(key, sort_keys=True), cd,
         key.get("snapshot"), query["auth_version"], query["version_digest"],
         json.dumps(sorted(cols)), json.dumps(sorted(orgs)), key["data_epoch"], now()),
    )
    conn.execute("INSERT INTO cache_payloads VALUES (?,?)", (entry_id, json.dumps(rows)))
    db.audit(conn, query["principal_id"], "cache.store", entry_id,
             {"query_id": query["query_id"], "key_digest": cd, "rows": len(rows)})
    return entry_id


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def execute_query(conn, query_id: str, delay: float | None = None) -> dict:
    query = get_query(conn, query_id)
    if query is None:
        raise authz.Denied("no_query", "query not found")
    if query["status"] in ("succeeded", "failed", "denied"):
        return {"query_id": query_id, "status": query["status"], "already_finished": True}

    plan = json.loads(query["plan_json"])
    delay = plan.get("slow_query_seconds", 0.0) if delay is None else delay
    conn.execute("UPDATE queries SET status='running', started_at=? WHERE query_id=?", (now(), query_id))

    if delay:
        time.sleep(delay)

    # Re-evaluate authorization *after* the slow read window so a revocation
    # that lands mid-query is observable.  pinned keeps its snapshot;
    # recheck intersects with the live grant.
    scope = execution_scope(conn, query)
    live = authz.live_grant(conn, query["principal_id"])
    plan["execution_scope"] = {
        "columns": scope["columns"], "organizations": scope["organizations"],
        "source": scope["source"], "live_version": scope["live_version"],
        "snapshot": scope["snapshot"], "snapshot_version": scope["snapshot_version"],
    }

    requested_cols = json.loads(query["requested_cols_json"])
    requested_orgs = json.loads(query["requested_orgs_json"])
    served_cols, withheld_cols = authz.intersect_columns(scope["columns"], requested_cols)
    served_orgs, withheld_orgs = authz.intersect_orgs(scope["organizations"], requested_orgs)
    plan["execution_scope"]["served_columns"] = served_cols
    plan["execution_scope"]["served_organizations"] = served_orgs
    plan["execution_scope"]["withheld_columns"] = withheld_cols
    plan["execution_scope"]["withheld_organizations"] = withheld_orgs

    if not served_cols or not served_orgs:
        denial = authz.record_denial(
            conn, query["principal_id"], "execution", "scope_emptied",
            "authorization was withdrawn before execution could read the requested scope",
            {
                "mode": query["auth_mode"],
                "launch_columns": json.loads(query["plan_json"]).get("served_columns_at_launch"),
                "launch_organizations": json.loads(query["plan_json"]).get("served_organizations_at_launch"),
                "live_version": live["version"],
                "live_columns": live["columns"],
                "live_organizations": live["organizations"],
                "withheld_columns": withheld_cols,
                "withheld_organizations": withheld_orgs,
            },
            query_id=query_id,
        )
        plan["failure"] = {"code": "scope_emptied", "denial_id": denial}
        fail(conn, query_id, "scope_emptied: no authorized data remains at execution time", plan)
        return {"query_id": query_id, "status": "failed", "code": "scope_emptied", "denial_id": denial}

    spec = json.loads(query["spec_json"])
    if plan.get("raw_sql"):
        sql = query["sql"]
        params: list = []
        measures = spec.get("measures") or []
        group_by = spec.get("group_by") or []
        # Row scope for raw SQL: wrap in a scoped subquery.  A raw query that
        # does not expose `organization` was rejected at launch.
        placeholders = ",".join("?" for _ in served_orgs)
        sql = (
            f"SELECT * FROM ({sql}) AS scoped "
            f"WHERE scoped.organization IN ({placeholders}) LIMIT 5000"
        )
        params = list(served_orgs)
    else:
        try:
            sql, params, measures, group_by = compile_spec(spec, served_cols, served_orgs)
        except ValueError as exc:
            denial = authz.record_denial(conn, query["principal_id"], "execution", "no_authorized_measure",
                                         str(exc), {"live_version": live["version"]}, query_id=query_id)
            fail(conn, query_id, f"no_authorized_measure: {exc}", {**plan, "failure": {"denial_id": denial}})
            return {"query_id": query_id, "status": "failed", "code": "no_authorized_measure", "denial_id": denial}
    plan["compiled_sql"] = _render(sql, params)
    plan["group_by"] = group_by
    plan["measures"] = measures

    key = make_cache_key(_render(sql, params), served_cols, served_orgs, query["data_epoch"])
    plan["cache_lookup_key"] = key
    plan["query_plan"] = explain(conn, sql, params)
    cached = find_cache(conn, key)
    plan["cache_candidates"] = cache_candidates(conn, key)
    db.audit(conn, query["principal_id"], "cache.lookup", query_id,
             {"key_digest": cache_key_digest(key), "hit": cached is not None,
              "columns": served_cols, "organizations": served_orgs})
    plan["cache"] = {"key_digest": cache_key_digest(key), "hit": cached is not None}
    if cached:
        plan["cache"]["entry"] = cached["entry"]["cache_entry_id"]
        plan["cache"]["created_by"] = cached["entry"]["created_by"]

    try:
        if cached:
            rows = cached["rows"]
            detail = _load_detail(conn, query_id)
            if detail is None:
                detail = _run_detail(conn, served_cols, served_orgs, spec)
                conn.execute("INSERT OR REPLACE INTO query_detail VALUES (?,?)", (query_id, json.dumps(detail)))
        else:
            rows = _run_aggregate(conn, sql, params)
            detail = _run_detail(conn, served_cols, served_orgs, spec)
            conn.execute("INSERT OR REPLACE INTO query_detail VALUES (?,?)", (query_id, json.dumps(detail)))
            entry_id = store_cache(conn, query, key, served_cols, served_orgs, rows)
            plan["cache"]["stored"] = entry_id
    except Exception as exc:  # noqa: BLE001
        fail(conn, query_id, f"execution_error: {exc}", plan)
        return {"query_id": query_id, "status": "failed", "error": str(exc)}

    conn.execute("INSERT OR REPLACE INTO query_results VALUES (?,?)", (query_id, json.dumps(rows)))
    conn.execute(
        "UPDATE queries SET status='succeeded', finished_at=?, row_count=?, cache_entry=?, plan_json=? WHERE query_id=?",
        (now(), len(rows), (plan.get("cache") or {}).get("entry") or (plan.get("cache") or {}).get("stored"),
         json.dumps(plan), query_id),
    )
    db.audit(conn, query["principal_id"], "query.finish", query_id,
             {"rows": len(rows), "cache_hit": bool(cached), "withheld_columns": withheld_cols,
              "withheld_organizations": withheld_orgs})
    return {
        "query_id": query_id, "status": "succeeded", "rows": len(rows),
        "cache": "hit" if cached else "miss",
        "withheld_columns": withheld_cols, "withheld_organizations": withheld_orgs,
    }


def _run_aggregate(conn, sql: str, params: list) -> list[dict]:
    cur = conn.execute(sql, params)
    return [dict(r) for r in cur.fetchall()]


def _run_detail(conn, served_cols: list[str], served_orgs: list[str], spec: dict) -> list[dict]:
    """Internal, scope-filtered detail rows used for safe narrower re-aggregation.

    Fetches every authorized fact column + keys, never delivered wholesale.
    """
    if not served_orgs:
        return []
    cols = sorted(set(served_cols) | {"row_key", "organization"})
    cols = [c for c in cols if c in db.BIZ_COLUMNS]
    where, params = authz.build_where(served_orgs, spec.get("filters"))
    sql = f"SELECT {', '.join('m.' + c for c in cols)} FROM metrics m WHERE {where} ORDER BY m.row_key"
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _load_detail(conn, query_id: str) -> list[dict] | None:
    row = conn.execute("SELECT rows_json FROM query_detail WHERE query_id=?", (query_id,)).fetchone()
    return json.loads(row["rows_json"]) if row else None


def get_result_rows(conn, query_id: str) -> list[dict]:
    row = conn.execute("SELECT rows_json FROM query_results WHERE query_id=?", (query_id,)).fetchone()
    return json.loads(row["rows_json"]) if row else []


def get_detail_rows(conn, query_id: str) -> list[dict]:
    return _load_detail(conn, query_id) or []


def fail(conn, query_id: str, error: str, plan: dict | None = None) -> None:
    conn.execute(
        "UPDATE queries SET status='failed', finished_at=?, error=?, plan_json=? WHERE query_id=?",
        (now(), error, json.dumps(plan or {}), query_id),
    )
    db.audit(conn, "system", "query.fail", query_id, {"error": error})
