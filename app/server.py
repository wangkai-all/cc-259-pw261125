"""HTTP server: JSON API + single-page UI.

No third-party dependencies.  ``python -m app.server`` starts it.
"""

from __future__ import annotations

import json
import mimetypes
import os
import re
import sys
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import authz, db, delivery, engine

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"

PRINCIPAL_HEADER = "X-Principal"


def json_default(obj):
    return str(obj)


class Handler(BaseHTTPRequestHandler):
    server_version = "ScaleGrant/1.0"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt, *args):  # quieter tests
        if os.environ.get("SHAN_VERBOSE"):
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, default=json_default, indent=2).encode()
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, code: str, reason: str, detail: dict | None = None):
        self._json(status, {"error": {"code": code, "reason": reason, "detail": detail or {}}})

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        if length > 1_000_000:
            raise ValueError("body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw)

    def _principal(self) -> str | None:
        q = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(q.query)
        pid = (params.get("principal") or [self.headers.get(PRINCIPAL_HEADER) or ""])[0]
        return pid or None

    def _require_principal(self) -> str | None:
        pid = self._principal()
        if not pid:
            self._error(401, "no_principal", "supply X-Principal header or ?principal=")
            return None
        row = db.connect().execute(
            "SELECT * FROM principals WHERE principal_id=?", (pid,)
        ).fetchone()
        if row is None:
            self._error(404, "unknown_principal", f"principal {pid} does not exist")
            return None
        return pid

    # -- transactions -----------------------------------------------------

    def _tx(self, fn):
        # Autocommit connections: no explicit commit needed.  rollback() is
        # a no-op but kept so error paths stay correct if isolation changes.
        conn = db.connect()
        try:
            fn()
        except authz.Denied as exc:
            conn.rollback()
            self._error(403, exc.code, exc.reason, exc.detail)
        except ValueError as exc:
            conn.rollback()
            self._error(400, "bad_request", str(exc))
        except Exception:  # noqa: BLE001
            conn.rollback()
            traceback.print_exc()
            self._error(500, "internal", "internal error")

    # -- routing ----------------------------------------------------------

    def do_GET(self):
        self._tx(self.route_get)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self._tx(self.route_post)

    def do_DELETE(self):
        self._tx(self.route_delete)

    def route_get(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        conn = db.connect()

        if path in ("/", "/index.html"):
            return self.serve_static("index.html")
        if path.startswith("/static/"):
            return self.serve_static(path[len("/static/"):])
        if path == "/api/meta":
            return self._json(200, meta_payload(conn))
        if path == "/api/grants":
            pid = qs.get("principal", [None])[0]
            return self._json(200, {"grants": grant_list(conn, pid)})
        if path == "/api/audit":
            return self._json(200, {"events": audit_list(conn, int((qs.get("limit") or ["60"])[0]))})
        if path == "/api/denials":
            pid = qs.get("principal", [None])[0]
            return self._json(200, {"denials": denial_list(conn, pid)})
        if path == "/api/cache":
            return self._json(200, {"entries": cache_list(conn)})
        if path == "/api/queries":
            pid = qs.get("principal", [None])[0]
            return self._json(200, {"queries": query_list(conn, pid)})
        m = re.match(r"^/api/queries/([^/]+)$", path)
        if m:
            return self.query_detail(conn, m.group(1))
        m = re.match(r"^/api/queries/([^/]+)/page$", path)
        if m:
            pid = self._require_principal()
            if not pid:
                return
            page = int((qs.get("page") or ["0"])[0])
            size = int((qs.get("page_size") or ["10"])[0])
            cursor = (qs.get("cursor") or [None])[0]
            return self._json(200, delivery.get_page(conn, m.group(1), pid, cursor, page, size))
        m = re.match(r"^/api/downloads/([^/]+)$", path)
        if m:
            job = conn.execute("SELECT * FROM download_jobs WHERE job_id=?", (m.group(1),)).fetchone()
            if not job:
                return self._error(404, "no_job", "job not found")
            return self._json(200, {"job": dict(job)})
        if path == "/api/downloads":
            pid = qs.get("principal", [None])[0]
            rows = conn.execute(
                "SELECT * FROM download_jobs WHERE principal_id=? ORDER BY created_at DESC LIMIT 30"
                if pid else
                "SELECT * FROM download_jobs ORDER BY created_at DESC LIMIT 30",
                ((pid,) if pid else ()),
            ).fetchall()
            return self._json(200, {"jobs": [dict(r) for r in rows]})
        return self._error(404, "not_found", f"no route {path}")

    def route_post(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        conn = db.connect()

        if path == "/api/query":
            pid = self._require_principal()
            if not pid:
                return
            body = self._body()
            qid = engine.create_query(
                conn, pid, body.get("spec") or {}, body.get("auth_mode") or "recheck",
                simulate_delay=body.get("delay") or 0,
                raw_sql=body.get("raw_sql"),
            )

            # Execute synchronously.  The UI drives the slow window with a
            # delay so a revocation can be applied from another tab while
            # the request is in flight.
            result = engine.execute_query(conn, qid)

            return self._json(200, {"query_id": qid, "execution": result,
                                    "query": query_view(conn, qid)})
        if path == "/api/downloads":
            pid = self._require_principal()
            if not pid:
                return
            body = self._body()
            res = delivery.start_download(conn, body.get("query_id"), pid,
                                          int(body.get("rows_per_chunk") or 15))

            return self._json(200, res)
        m = re.match(r"^/api/downloads/([^/]+)/resume$", path)
        if m:
            pid = self._require_principal()
            if not pid:
                return
            body = self._body()
            res = delivery.resume_download(conn, m.group(1), pid,
                                           int(body.get("chunks") or 1),
                                           float(body.get("delay") or 0))

            return self._json(200, res)
        if path == "/api/grants":
            pid = self._require_principal()
            if not pid:
                return
            row = conn.execute("SELECT role FROM principals WHERE principal_id=?", (pid,)).fetchone()
            if not row or row["role"] != "admin":
                return self._error(403, "admin_required", "only admins may publish grants")
            body = self._body()
            target = body.get("principal_id") or ""
            if not conn.execute("SELECT 1 FROM principals WHERE principal_id=?", (target,)).fetchone():
                return self._error(404, "unknown_principal", "target principal does not exist")
            res = publish_from_body(conn, target, body, actor=pid)

            return self._json(200, res)
        if path == "/api/admin/reset":
            pid = self._require_principal()
            if not pid:
                return
            row = conn.execute("SELECT role FROM principals WHERE principal_id=?", (pid,)).fetchone()
            if not row or row["role"] != "admin":
                return self._error(403, "admin_required", "only admins may reset")
            conn.close()
            db.init(force=True)
            return self._json(200, {"status": "reset"})
        if path == "/api/demo/revoke":
            # convenience endpoint used by the "sample scenario" button
            return self.composite_revoke(conn)
        return self._error(404, "not_found", f"no route {path}")

    def route_delete(self):
        return self._error(404, "not_found", "nothing to delete")

    # -- composites -------------------------------------------------------

    def composite_revoke(self, conn):
        body = self._body()
        pid = self._require_principal()
        if not pid:
            return
        actor = conn.execute("SELECT role FROM principals WHERE principal_id=?", (pid,)).fetchone()
        if not actor or actor["role"] != "admin":
            return self._error(403, "admin_required", "only admins may run the scenario")
        res = run_revoke_scenario(conn)

        return self._json(200, res)

    def query_detail(self, conn, qid):
        query = engine.get_query(conn, qid)
        if not query:
            return self._error(404, "no_query", "query not found")
        return self._json(200, {
            "query": query_view(conn, qid),
            "plan": json.loads(query["plan_json"] or "{}"),
            "result_preview": engine.get_result_rows(conn, qid)[:50],
        })

    def serve_static(self, name: str):
        safe = Path(name).name
        candidate = (STATIC / safe).resolve()
        if not str(candidate).startswith(str(STATIC.resolve())) or not candidate.is_file():
            return self._error(404, "not_found", f"no static file {name}")
        ctype = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if candidate.suffix == ".js":
            ctype = "text/javascript; charset=utf-8"
        self._send(200, candidate.read_bytes(), ctype)


# ---------------------------------------------------------------------------
# Read models
# ---------------------------------------------------------------------------


def meta_payload(conn) -> dict:
    principals = [dict(r) for r in conn.execute("SELECT * FROM principals ORDER BY principal_id")]
    for p in principals:
        g = authz.live_grant(conn, p["principal_id"])
        p["grant"] = g
    return {
        "principals": principals,
        "organizations": [{"id": k, "label": v[0], "team": v[1]} for k, v in db.SAMPLE_ORGS.items()],
        "dimensions": engine.DIMENSIONS,
        "measures": engine.MEASURES,
        "columns": list(db.BIZ_COLUMNS),
        "data_epoch": authz.data_epoch(conn),
        "policy": {
            "execution": "pinned snapshot at launch, or live ∩ launch in recheck mode",
            "delivery": "every page/chunk is re-authorized against the live grant",
            "delivered": "frozen pages are immutable; already-downloaded chunks are never recalled",
            "cache": "shared by scope; entries are never deleted on revocation and never served to a narrower scope",
            "cursor": "bound to query + principal; replay of a frozen page returns identical bytes",
        },
    }


def grant_list(conn, principal: str | None) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM grant_versions ORDER BY principal_id, version"
    ).fetchall()
    out = []
    for r in rows:
        if principal and r["principal_id"] != principal:
            continue
        g = authz._grant_for_version(conn, r["version"])
        out.append({
            "version": r["version"], "principal_id": r["principal_id"],
            "status": r["status"], "created_at": r["created_at"],
            "created_by": r["created_by"], "note": r["note"],
            "columns": g["columns"], "organizations": g["organizations"],
            "digest": authz.digest_of(g["columns"], g["organizations"]),
        })
    return out


def publish_from_body(conn, target: str, body: dict, actor: str) -> dict:
    current = authz.live_grant(conn, target)
    columns = body.get("columns", current["columns"])
    organizations = body.get("organizations", current["organizations"])
    note = body.get("note") or "published from UI"
    res = authz.publish_grant(conn, target, columns, organizations, actor, note)
    return {**res, "grant": authz.live_grant(conn, target)}


def query_list(conn, principal: str | None) -> list[dict]:
    if principal:
        rows = conn.execute(
            "SELECT * FROM queries WHERE principal_id=? ORDER BY created_at DESC LIMIT 40",
            (principal,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM queries ORDER BY created_at DESC LIMIT 40").fetchall()
    return [query_view(conn, r["query_id"]) for r in rows]


def query_view(conn, qid: str) -> dict:
    q = engine.get_query(conn, qid)
    if not q:
        return {}
    plan = json.loads(q["plan_json"] or "{}")
    return {
        "query_id": q["query_id"], "principal_id": q["principal_id"], "sql": q["sql"],
        "status": q["status"], "auth_mode": q["auth_mode"],
        "auth_snapshot": q["auth_snapshot"], "auth_version": q["auth_version"],
        "version_digest": q["version_digest"], "created_at": q["created_at"],
        "finished_at": q["finished_at"], "row_count": q["row_count"],
        "error": q["error"], "cache_entry": q["cache_entry"],
        "requested_columns": json.loads(q["requested_cols_json"]),
        "requested_organizations": json.loads(q["requested_orgs_json"]),
        "plan": plan,
    }


def cache_list(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM cache_entries ORDER BY created_at DESC").fetchall()
    out = []
    for r in rows:
        payload = conn.execute(
            "SELECT rows_json FROM cache_payloads WHERE cache_entry_id=?", (r["cache_entry_id"],)
        ).fetchone()
        rows_count = len(json.loads(payload["rows_json"])) if payload else 0
        out.append({
            "cache_entry_id": r["cache_entry_id"], "created_by": r["created_by"],
            "key_digest": r["key_digest"], "sql": r["sql"],
            "columns": json.loads(r["scope_cols_json"]),
            "organizations": json.loads(r["scope_orgs_json"]),
            "auth_version": r["auth_version"], "auth_snapshot": r["auth_snapshot"],
            "data_epoch": r["data_epoch"], "row_count": rows_count,
            "created_at": r["created_at"], "key": json.loads(r["key_json"]),
        })
    return out


def denial_list(conn, principal: str | None) -> list[dict]:
    if principal:
        rows = conn.execute(
            "SELECT * FROM denials WHERE principal_id=? ORDER BY at DESC LIMIT 40", (principal,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM denials ORDER BY at DESC LIMIT 40").fetchall()
    return [{**dict(r), "detail": json.loads(r["detail_json"])} for r in rows]


def audit_list(conn, limit: int = 60) -> list[dict]:
    rows = conn.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(r), "detail": json.loads(r["detail_json"])} for r in rows]


# ---------------------------------------------------------------------------
# Sample scenario: revocation racing a restored job
# ---------------------------------------------------------------------------


def run_revoke_scenario(conn) -> dict:
    """Build a reproducible 'revocation meets job resume' demo.

    1. admin publishes Ada's initial grant (if needed) and launches a
       pinned query.
    2. A page is delivered (frozen).
    3. Ada starts a slow download job paused after creation.
    4. Admin revokes organization 'south' and column 'orders' from Ada.
    5. The job is resumed; chunk delivery re-authorizes and withholds the
       revoked scope, then a second revoke removes 'north' too, which stops
       the job at a chunk boundary.
    6. Cursor replay of the frozen page still returns the original bytes.
    """
    admin = "admin-root"
    grace = authz.publish_grant(
        conn, "analyst-ada", ["organization", "segment", "occurred_at", "revenue_cents", "orders"],
        ["north", "south", "east"], admin, "scenario: restore broad grant",
    )
    spec = {
        "group_by": ["organization"],
        "measures": ["revenue_cents", "orders"],
        "organization": ["north", "south", "east"],
        "order_by": "organization",
    }
    qid = engine.create_query(conn, "analyst-ada", spec, "pinned")

    exec_res = engine.execute_query(conn, qid)

    page = delivery.get_page(conn, qid, "analyst-ada", None, 0, 5)

    job = delivery.start_download(conn, qid, "analyst-ada", rows_per_chunk=1)


    # revoke 'south' + 'orders'
    authz.publish_grant(
        conn, "analyst-ada", ["organization", "segment", "occurred_at", "revenue_cents"],
        ["north", "east"], admin, "scenario: revoke south + orders",
    )


    resumed = delivery.resume_download(conn, job.get("job_id", ""), "analyst-ada", chunks=1)


    replay = delivery.get_page(
        conn, qid, "analyst-ada", page.get("cursor_id"), page.get("page", 0), 5
    )


    next_page = delivery.get_page(
        conn, qid, "analyst-ada", page.get("cursor_id"), page.get("page", 0) + 1, 5
    )


    download_after = conn.execute(
        "SELECT * FROM download_jobs WHERE job_id=?", (job.get("job_id"),)
    ).fetchone()

    return {
        "scenario": "revocation-meets-resume",
        "steps": [
            {"step": "grant restored", "result": grace},
            {"step": "pinned query launched", "query_id": qid},
            {"step": "query executed", "execution": exec_res},
            {"step": "page 0 delivered (frozen)", "page": {
                "row_count": page.get("row_count"), "columns": page.get("columns"),
                "rows": page.get("rows"), "cursor": page.get("cursor_id")}},
            {"step": "download job created paused", "job": job},
            {"step": "grant revoked", "revoked": {"organization": "south", "column": "orders"}},
            {"step": "job resumed after revocation", "resume": resumed},
            {"step": "frozen page replayed", "replay": {
                "replay": replay.get("replay"), "row_count": replay.get("row_count"),
                "columns": replay.get("columns"), "rows": replay.get("rows")}},
            {"step": "page 1 after revocation", "next_page": next_page},
            {"step": "job state", "job": dict(download_after) if download_after else None},
        ],
        "query_id": qid,
        "cursor_id": page.get("cursor_id"),
        "job_id": job.get("job_id"),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    db.init()
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main(argv: list[str]) -> int:
    host = os.environ.get("SHAN_HOST", "127.0.0.1")
    port = int(os.environ.get("SHAN_PORT", "8765"))
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    if "--host" in argv:
        host = argv[argv.index("--host") + 1]
    if "--reset" in argv:
        db.init(force=True)
    server = build_server(host, port)
    print(f"serving on http://{host}:{port}  (db: {db.DB_PATH})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
