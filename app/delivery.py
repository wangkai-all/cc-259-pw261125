"""Delivery layer: paged results, cursors, cache reuse and download chunks.

Three invariants:

A. Delivered bytes are immutable.  A page is frozen in ``page_deliveries``.
   Re-requesting the same page returns those exact bytes even after a
   revocation -- we cannot recall what the client already has.

B. Undelivered bytes are re-authorized against the *live* grant at the
   moment of delivery.  A revoked column is withheld; revoked organizations
   are dropped and aggregates are recomputed from scope-filtered detail so
   a stale SUM can never embed revoked rows.

C. Caches are shared, not owned.  Revoking one principal never deletes an
   entry another principal with sufficient scope still needs.  A cache entry
   is only usable by a caller whose live grant covers its full column and
   row scope; if not, the caller recomputes a narrower aggregate.
"""

from __future__ import annotations

import json
import secrets
import time

from . import authz, db, engine



def _project(rows: list[dict], columns: list[str]) -> list[dict]:
    return [{c: r.get(c) for c in columns if c in r} for r in rows]


def _aggregate(detail: list[dict], columns: list[str], spec: dict) -> list[dict]:
    group_by = [g for g in (spec.get("group_by") or []) if g in columns]
    measures = [m for m in (spec.get("measures") or []) if m in columns]
    if not measures:
        return []
    buckets: dict[tuple, list[dict]] = {}
    for r in detail:
        buckets.setdefault(tuple(r.get(g) for g in group_by), []).append(r)
    out = []
    for key, group in buckets.items():
        rec = dict(zip(group_by, key))
        for m in measures:
            if m == "orders":
                rec[m] = len(group)
            elif m == "active_users":
                rec[m] = max((r.get(m) or 0) for r in group)
            else:
                rec[m] = sum((r.get(m) or 0) for r in group)
        if "organization" in columns and "organization" not in rec:
            rec["organization"] = group[0].get("organization")
        if "occurred_at" in columns and "occurred_at" not in rec:
            rec["occurred_at"] = group[0].get("occurred_at")
        if "segment" in columns and "segment" not in rec:
            rec["segment"] = group[0].get("segment")
        out.append(rec)
    if group_by:
        order = spec.get("order_by") if spec.get("order_by") in group_by else group_by[0]
        out.sort(key=lambda r: str(r.get(order)), reverse=bool(spec.get("order_desc")))
    return out


def _live_delivery_scope(conn, query: dict) -> dict:
    """Effective delivery scope = execution scope ∩ live grant."""
    plan = json.loads(query["plan_json"])
    ex = plan.get("execution_scope") or {}
    live = authz.live_grant(conn, query["principal_id"])
    requested_cols = json.loads(query["requested_cols_json"])
    requested_orgs = json.loads(query["requested_orgs_json"])
    base_cols = ex.get("served_columns") or plan.get("served_columns_at_launch") or []
    base_orgs = ex.get("served_organizations") or plan.get("served_organizations_at_launch") or []
    # Without an execution scope the query never got far enough to deliver.
    cols = sorted(set(base_cols) & set(live["columns"]))
    orgs = sorted(set(base_orgs) & set(live["organizations"]))
    withheld_cols = [c for c in requested_cols if c not in set(cols)]
    withheld_orgs = [o for o in requested_orgs if o not in set(orgs)]
    return {
        "columns": cols,
        "organizations": orgs,
        "withheld_columns": withheld_cols,
        "withheld_organizations": withheld_orgs,
        "live_version": live["version"],
        "live_digest": live["digest"],
        "execution_columns": base_cols,
        "execution_organizations": base_orgs,
    }


def _scoped_rows(conn, query: dict, scope: dict) -> tuple[list[dict], bool]:
    """Rows deliverable right now.  Returns (rows, recomputed).

    Aggregates are always recomputed from detail when the live scope differs
    from the execution scope, so withdrawn rows cannot survive inside a SUM.
    """
    spec = json.loads(query["spec_json"])
    plan = json.loads(query["plan_json"])
    is_aggregate = bool(plan.get("group_by"))
    narrowed = (
        set(scope["columns"]) != set(scope["execution_columns"])
        or set(scope["organizations"]) != set(scope["execution_organizations"])
    )
    detail = engine.get_detail_rows(conn, query["query_id"])
    if is_aggregate and narrowed:
        detail = [r for r in detail if r.get("organization") in set(scope["organizations"])]
        return _project(_aggregate(detail, scope["columns"], spec), scope["columns"]), True
    rows = engine.get_result_rows(conn, query["query_id"])
    if not is_aggregate:
        rows = [r for r in rows if r.get("organization") in set(scope["organizations"])]
        return _project(rows, scope["columns"]), False
    return _project(rows, scope["columns"]), False


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def _row_identity(row: dict, group_by: list[str]) -> str:
    """Stable identity for pagination across scope changes."""
    if "row_key" in row:
        return "rk:" + str(row["row_key"])
    if group_by:
        return "g:" + json.dumps([row.get(g) for g in group_by], sort_keys=True)
    return "r:" + json.dumps(row, sort_keys=True)


def _delivered_identities(conn, query_id: str, principal: str, group_by: list[str]) -> set[str]:
    """Identities already handed to this principal, from frozen pages only."""
    rows = conn.execute(
        "SELECT rows_json FROM page_deliveries WHERE query_id=? AND principal_id=?",
        (query_id, principal),
    ).fetchall()
    seen: set[str] = set()
    for r in rows:
        for row in json.loads(r["rows_json"]):
            seen.add(_row_identity(row, group_by))
    return seen


def _delivered_page(conn, query_id: str, page: int, principal: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM page_deliveries WHERE query_id=? AND page_index=? AND principal_id=?",
        (query_id, page, principal),
    ).fetchone()
    return dict(row) if row else None


def get_page(conn, query_id: str, principal: str, cursor_id: str | None, page: int, page_size: int) -> dict:
    query = engine.get_query(conn, query_id)
    if query is None:
        return {"status": "denied", "code": "no_query", "reason": "query not found"}
    if query["principal_id"] != principal:
        denial = authz.record_denial(
            conn, principal, "page", "cursor_principal_mismatch",
            "the cursor was issued to a different principal; cursors are bound to their owner",
            {"query_owner": query["principal_id"], "cursor": cursor_id},
            query_id=query_id,
        )
        return {"status": "denied", "code": "cursor_principal_mismatch",
                "reason": "cursors are bound to the principal they were issued to",
                "denial_id": denial}
    if query["status"] != "succeeded":
        return {"status": "denied", "code": "query_not_ready", "reason": f"query is {query['status']}"}

    if cursor_id:
        cur = conn.execute("SELECT * FROM delivery_cursors WHERE cursor_id=?", (cursor_id,)).fetchone()
        if cur is None or cur["query_id"] != query_id or cur["principal_id"] != principal:
            denial = authz.record_denial(
                conn, principal, "page", "bad_cursor",
                "cursor does not belong to this query and principal",
                {"cursor": cursor_id}, query_id=query_id,
            )
            return {"status": "denied", "code": "bad_cursor",
                    "reason": "this cursor is not valid for this query and principal",
                    "denial_id": denial}
    else:
        cursor_id = f"cur-{secrets.token_hex(6)}"
        conn.execute("INSERT INTO delivery_cursors VALUES (?,?,?,?)",
                     (cursor_id, query_id, principal, time.time()))

    page = max(0, page)
    page_size = max(1, min(page_size, 500))

    frozen = _delivered_page(conn, query_id, page, principal)
    if frozen is not None:
        return _payload(frozen, replay=True, cursor_id=cursor_id)

    scope = _live_delivery_scope(conn, query)
    withheld_cols = scope["withheld_columns"]
    withheld_orgs = scope["withheld_organizations"]

    if not scope["columns"] or not scope["organizations"]:
        denial = authz.record_denial(
            conn, principal, "page", "scope_revoked",
            "no requested data remains authorized for delivery",
            {"page": page, "live_version": scope["live_version"],
             "withheld_columns": withheld_cols, "withheld_organizations": withheld_orgs},
            query_id=query_id,
        )
        return {"status": "denied", "code": "scope_revoked",
                "reason": "authorization for the remaining scope was withdrawn before this page was delivered",
                "withheld_columns": withheld_cols, "withheld_organizations": withheld_orgs,
                "denial_id": denial, "cursor_id": cursor_id}

    rows, recomputed = _scoped_rows(conn, query, scope)
    # Pagination is by *row identity*, not offset: a revocation that removes
    # organizations must not shift the undelivered window and cause a row to
    # be skipped or repeated.  Already-delivered identities are excluded.
    spec = json.loads(query["spec_json"])
    group_by = [g for g in (spec.get("group_by") or []) if g in scope["columns"]]
    seen = _delivered_identities(conn, query_id, principal, group_by)
    undelivered = [r for r in rows if _row_identity(r, group_by) not in seen]
    page_rows = undelivered[:page_size]

    if withheld_cols or withheld_orgs:
        authz.record_denial(
            conn, principal, "page", "partial_scope_withheld",
            "page served with withdrawn data withheld and aggregates recomputed",
            {"page": page, "withheld_columns": withheld_cols,
             "withheld_organizations": withheld_orgs,
             "live_version": scope["live_version"], "recomputed": recomputed},
            query_id=query_id,
        )

    if not page_rows:
        return {
            "status": "exhausted",
            "code": "nothing_left_to_deliver" if withheld_cols or withheld_orgs else "end_of_results",
            "reason": ("remaining rows fall outside the live grant after revocation; "
                       "nothing new can be delivered"
                       if withheld_cols or withheld_orgs else "no more rows"),
            "withheld_columns": withheld_cols,
            "withheld_organizations": withheld_orgs,
            "cursor_id": cursor_id,
            "total_deliverable": len(rows),
        }

    page_id = f"pg-{secrets.token_hex(6)}"
    conn.execute(
        "INSERT INTO page_deliveries(page_id,query_id,cursor_id,page_index,principal_id,policy,"
        "auth_snapshot,auth_version,served_cols_json,served_orgs_json,withheld_cols_json,"
        "withheld_orgs_json,rows_json,row_count,reshaped,created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (page_id, query_id, cursor_id, page, principal, query["auth_mode"],
         query["auth_snapshot"], scope["live_version"],
         json.dumps(scope["columns"]), json.dumps(scope["organizations"]),
         json.dumps(withheld_cols), json.dumps(withheld_orgs),
         json.dumps(page_rows), len(page_rows), 1 if recomputed else 0, time.time()),
    )
    frozen = _delivered_page(conn, query_id, page, principal)
    result = _payload(frozen, replay=False, cursor_id=cursor_id)
    result["total_deliverable"] = len(rows)
    return result


def _payload(row: dict, replay: bool, cursor_id: str) -> dict:
    return {
        "status": "delivered",
        "replay": replay,
        "page": row["page_index"],
        "cursor_id": row["cursor_id"] if not replay else cursor_id,
        "columns": json.loads(row["served_cols_json"]),
        "organizations": json.loads(row["served_orgs_json"]),
        "withheld_columns": json.loads(row["withheld_cols_json"]),
        "withheld_organizations": json.loads(row["withheld_orgs_json"]),
        "rows": json.loads(row["rows_json"]),
        "row_count": row["row_count"],
        "recomputed_from_detail": bool(row["reshaped"]),
        "auth_version": row["auth_version"],
        "frozen_at": row["created_at"],
        "immutable_note": "delivered bytes are frozen and cannot be recalled",
    }


# ---------------------------------------------------------------------------
# Downloads
# ---------------------------------------------------------------------------


def start_download(conn, query_id: str, principal: str, rows_per_chunk: int = 15) -> dict:
    query = engine.get_query(conn, query_id)
    if query is None:
        return {"status": "denied", "code": "no_query", "reason": "query not found"}
    if query["principal_id"] != principal:
        denial = authz.record_denial(conn, principal, "download", "not_owner",
                                     "download jobs are bound to the query owner", {}, query_id=query_id)
        return {"status": "denied", "code": "not_owner", "reason": "not your query", "denial_id": denial}
    if query["status"] != "succeeded":
        return {"status": "denied", "code": "query_not_ready", "reason": f"query is {query['status']}"}

    scope = _live_delivery_scope(conn, query)
    if not scope["columns"] or not scope["organizations"]:
        denial = authz.record_denial(
            conn, principal, "download", "scope_revoked",
            "no requested data remains authorized to download",
            {"withheld_columns": scope["withheld_columns"],
             "withheld_organizations": scope["withheld_organizations"]},
            query_id=query_id,
        )
        return {"status": "denied", "code": "scope_revoked",
                "reason": "authorization withdrawn before the download could start",
                "withheld_columns": scope["withheld_columns"],
                "withheld_organizations": scope["withheld_organizations"],
                "denial_id": denial}

    rows, recomputed = _scoped_rows(conn, query, scope)
    rows_per_chunk = max(1, min(rows_per_chunk, 200))
    chunks = [rows[i:i + rows_per_chunk] for i in range(0, len(rows), rows_per_chunk)] or [[]]
    job_id = f"job-{secrets.token_hex(5)}"
    conn.execute(
        "INSERT INTO download_jobs(job_id,query_id,principal_id,status,created_at,updated_at,"
        "auth_snapshot,auth_version,chunks_total,chunks_done,rows_total,rows_done,rows_per_chunk,note)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (job_id, query_id, principal, "paused", time.time(), time.time(),
         query["auth_snapshot"], scope["live_version"], len(chunks), 0,
         len(rows), 0, rows_per_chunk, "created paused; resume one chunk at a time"),
    )
    for i, chunk in enumerate(chunks):
        conn.execute("INSERT INTO download_chunks VALUES (?,?,?)", (job_id, i, json.dumps(chunk)))
    db.audit(conn, principal, "download.create", job_id,
             {"query_id": query_id, "chunks": len(chunks), "rows": len(rows),
              "withheld_columns": scope["withheld_columns"],
              "withheld_organizations": scope["withheld_organizations"]})
    return {"status": "created", "job_id": job_id, "chunks_total": len(chunks),
            "rows_total": len(rows), "rows_per_chunk": rows_per_chunk,
            "recomputed_from_detail": recomputed,
            "withheld_columns": scope["withheld_columns"],
            "withheld_organizations": scope["withheld_organizations"]}


def resume_download(conn, job_id: str, principal: str, chunks: int = 1, delay: float = 0.0) -> dict:
    job = conn.execute("SELECT * FROM download_jobs WHERE job_id=?", (job_id,)).fetchone()
    if job is None:
        return {"status": "denied", "code": "no_job", "reason": "job not found"}
    job = dict(job)
    if job["principal_id"] != principal:
        denial = authz.record_denial(conn, principal, "download", "not_owner",
                                     "download jobs are bound to their creator", {}, job_id=job_id)
        return {"status": "denied", "code": "not_owner", "reason": "not your job", "denial_id": denial}
    if job["status"] in ("completed", "revoked"):
        return {"status": job["status"], "code": f"job_{job['status']}",
                "reason": "job already finished", "rows_done": job["rows_done"],
                "chunks_done": job["chunks_done"], "chunks_total": job["chunks_total"]}

    if delay:
        time.sleep(max(0.0, min(delay, 8.0)))

    query = engine.get_query(conn, job["query_id"])
    scope = _live_delivery_scope(conn, query)

    if not scope["columns"] or not scope["organizations"]:
        denial = authz.record_denial(
            conn, principal, "download", "chunk_scope_revoked",
            "authorization for all remaining data was withdrawn at a chunk boundary; job stopped",
            {"chunks_done": job["chunks_done"], "chunks_total": job["chunks_total"],
             "withheld_columns": scope["withheld_columns"],
             "withheld_organizations": scope["withheld_organizations"]},
            query_id=job["query_id"], job_id=job_id,
        )
        conn.execute(
            "UPDATE download_jobs SET status='revoked', updated_at=?, last_denial=?, note=? WHERE job_id=?",
            (time.time(), denial,
             "stopped at a chunk boundary: no requested data remains authorized", job_id),
        )
        db.audit(conn, principal, "download.revoke", job_id,
                 {"denial_id": denial, "chunks_done": job["chunks_done"]})
        return {"status": "revoked", "code": "chunk_scope_revoked",
                "reason": "authorization withdrawn before the next chunk was delivered",
                "chunks_done": job["chunks_done"], "chunks_total": job["chunks_total"],
                "rows_done": job["rows_done"],
                "withheld_columns": scope["withheld_columns"],
                "withheld_organizations": scope["withheld_organizations"],
                "denial_id": denial}

    # Rebuild deliverable rows under the live grant; aggregates recompute.
    # Delivery is identity-based: rows already handed over are never repeated,
    # and a revocation between chunks cannot shift the window past an
    # authorized row.
    rows, recomputed = _scoped_rows(conn, query, scope)
    spec = json.loads(query["spec_json"])
    group_by = [g for g in (spec.get("group_by") or []) if g in scope["columns"]]
    already = {
        r["identity"]
        for r in conn.execute(
            "SELECT identity FROM download_delivered WHERE job_id=?", (job_id,)
        )
    }
    undelivered = [r for r in rows if _row_identity(r, group_by) not in already]
    rows_per_chunk = job["rows_per_chunk"]
    delivered = []
    done = job["chunks_done"]
    limit = max(1, min(chunks, job["chunks_total"] - done))
    cursor = 0
    for _ in range(limit):
        chunk_rows = undelivered[cursor:cursor + rows_per_chunk]
        cursor += rows_per_chunk
        if not chunk_rows:
            break
        for row in chunk_rows:
            conn.execute(
                "INSERT OR IGNORE INTO download_delivered VALUES (?,?,?)",
                (job_id, _row_identity(row, group_by), done),
            )
        delivered.append({"chunk": done, "rows": chunk_rows, "row_count": len(chunk_rows)})
        done += 1

    if scope["withheld_columns"] or scope["withheld_organizations"]:
        authz.record_denial(
            conn, principal, "download", "partial_scope_withheld",
            "chunk delivered with withdrawn data withheld and aggregates recomputed",
            {"withheld_columns": scope["withheld_columns"],
             "withheld_organizations": scope["withheld_organizations"],
             "live_version": scope["live_version"], "recomputed": recomputed},
            query_id=job["query_id"], job_id=job_id,
        )

    rows_done = job["rows_done"] + sum(c["row_count"] for c in delivered)
    # "completed" means every row the live grant allows has been handed over.
    # When a revocation shrank the job, the remaining chunks are permanently
    # undeliverable; say so explicitly instead of reporting a bare success.
    withheld = scope["withheld_columns"] or scope["withheld_organizations"]
    exhausted = cursor >= len(undelivered)
    status = "completed" if (done >= job["chunks_total"] or exhausted) else "paused"
    if status == "completed" and done < job["chunks_total"] and withheld:
        note = (f"stopped at chunk {done}/{job['chunks_total']}: remaining chunks cannot be "
                f"delivered because authorization was withdrawn")
    elif status == "completed":
        note = "completed"
    else:
        note = f"paused at chunk {done}/{job['chunks_total']}"
    conn.execute(
        "UPDATE download_jobs SET chunks_done=?, rows_done=?, status=?, updated_at=?, note=? WHERE job_id=?",
        (done, rows_done, status, time.time(), note, job_id),
    )
    db.audit(conn, principal, "download.resume", job_id,
             {"chunks": [c["chunk"] for c in delivered], "rows": sum(c["row_count"] for c in delivered),
              "live_version": scope["live_version"], "recomputed": recomputed,
              "withheld": {"columns": scope["withheld_columns"],
                           "organizations": scope["withheld_organizations"]}})
    return {
        "status": status, "job_id": job_id, "chunks_done": done,
        "chunks_total": job["chunks_total"], "rows_done": rows_done,
        "rows_total": job["rows_total"], "chunks": delivered,
        "note": note,
        "truncated_by_revocation": bool(status == "completed" and done < job["chunks_total"] and withheld),
        "recomputed_from_detail": recomputed,
        "withheld_columns": scope["withheld_columns"],
        "withheld_organizations": scope["withheld_organizations"],
    }
