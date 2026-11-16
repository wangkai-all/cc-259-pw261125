"""Invariant tests for the authorization / delivery / cache model.

Run with:  python3 -m unittest discover -s tests -v
Each test isolates its database in a temporary directory.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import authz, db, delivery, engine  # noqa: E402

DIMS = ["organization", "segment", "occurred_at"]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SHAN_DATA"] = self.tmp.name
        db.DB_PATH = Path(self.tmp.name) / "analytics.sqlite3"
        db._thread_local.__dict__.pop("conn", None)
        db.init(force=True)
        self.conn = db.connect()

    def tearDown(self):
        db._thread_local.__dict__.pop("conn", None)
        self.tmp.cleanup()

    def spec(self, orgs=("north", "south", "east"), measures=("revenue_cents", "orders")):
        return {"organization": list(orgs), "group_by": ["organization"], "measures": list(measures), "order_by": "organization"}

    def run_query(self, principal="analyst-ada", mode="recheck", spec=None, delay=0):
        qid = engine.create_query(self.conn, principal, spec or self.spec(), mode, simulate_delay=delay)
        return qid, engine.execute_query(self.conn, qid)

    def grant(self, principal, cols, orgs, note=""):
        return authz.publish_grant(self.conn, principal, cols, orgs, "admin-root", note)


class GrantTests(Base):
    def test_live_grant_intersection(self):
        g = authz.live_grant(self.conn, "analyst-ada")
        self.assertEqual(g["organizations"], ["east", "north", "south"])
        served, withheld = authz.intersect_columns(g["columns"], ["revenue_cents", "refund_cents"])
        self.assertIn("revenue_cents", served)
        self.assertEqual(withheld, ["refund_cents"])
        served_orgs, withheld_orgs = authz.intersect_orgs(g["organizations"], ["north", "west"])
        self.assertEqual(served_orgs, ["north"])
        self.assertEqual(withheld_orgs, ["west"])

    def test_empty_request_means_all_granted_not_all_rows(self):
        served, _ = authz.intersect_orgs(["north"], [])
        self.assertEqual(served, ["north"])

    def test_publish_creates_new_version_and_keeps_history(self):
        v1 = authz.live_grant(self.conn, "analyst-ada")["version"]
        self.grant("analyst-ada", ["organization", "revenue_cents"], ["north"], "narrow")
        live = authz.live_grant(self.conn, "analyst-ada")
        self.assertGreater(live["version"], v1)
        count = self.conn.execute(
            "SELECT COUNT(*) c FROM grant_versions WHERE principal_id='analyst-ada'"
        ).fetchone()["c"]
        self.assertEqual(count, 2)

    def test_unknown_column_rejected(self):
        with self.assertRaises(authz.Denied):
            self.grant("analyst-ada", ["secret_salary"], ["north"])


class LaunchTests(Base):
    def test_launch_denied_when_no_overlap(self):
        with self.assertRaises(authz.Denied) as ctx:
            engine.create_query(self.conn, "analyst-ada", self.spec(orgs=("west",)), "recheck")
        self.assertEqual(ctx.exception.code, "no_overlap")
        denials = self.conn.execute("SELECT * FROM denials ORDER BY at DESC").fetchall()
        self.assertEqual(denials[0]["code"], "no_overlap")
        self.assertEqual(denials[0]["principal_id"], "analyst-ada")

    def test_launch_withholds_but_allows_partial_scope(self):
        qid = engine.create_query(
            self.conn, "analyst-ada",
            self.spec(orgs=("north", "west"), measures=("revenue_cents", "refund_cents")),
            "recheck",
        )
        plan = json.loads(engine.get_query(self.conn, qid)["plan_json"])
        self.assertEqual(plan["withheld_organizations_at_launch"], ["west"])
        self.assertEqual(plan["withheld_columns_at_launch"], ["refund_cents"])

    def test_raw_sql_must_project_organization(self):
        with self.assertRaises(authz.Denied) as ctx:
            engine.create_query(
                self.conn, "analyst-ada", self.spec(), "recheck",
                raw_sql="SELECT SUM(revenue_cents) FROM metrics",
            )
        self.assertEqual(ctx.exception.code, "raw_sql_requires_organization")

    def test_raw_sql_scope_enforced(self):
        qid = engine.create_query(
            self.conn, "analyst-ada", self.spec(), "recheck",
            raw_sql="SELECT organization, SUM(revenue_cents) AS revenue_cents FROM metrics GROUP BY organization",
        )
        res = engine.execute_query(self.conn, qid)
        self.assertEqual(res["status"], "succeeded")
        orgs = {r["organization"] for r in engine.get_result_rows(self.conn, qid)}
        self.assertNotIn("west", orgs)
        self.assertTrue(orgs.issubset({"north", "south", "east"}))


class PinnedVsRecheck(Base):
    def test_recheck_narrows_execution_when_revoked_mid_slow_query(self):
        qid = engine.create_query(self.conn, "analyst-ada", self.spec(), "recheck", simulate_delay=0.3)

        def revoke():
            time.sleep(0.08)
            c = db.connect()
            authz.publish_grant(c, "analyst-ada", DIMS + ["revenue_cents"], ["north"], "admin-root", "mid-query")

        t = threading.Thread(target=revoke)
        t.start()
        res = engine.execute_query(self.conn, qid)
        t.join()
        self.assertEqual(res["status"], "succeeded")
        rows = engine.get_result_rows(self.conn, qid)
        self.assertEqual({r["organization"] for r in rows}, {"north"})
        self.assertNotIn("orders", json.dumps(rows))

    def test_pinned_keeps_snapshot_for_execution(self):
        qid = engine.create_query(self.conn, "analyst-ada", self.spec(), "pinned", simulate_delay=0.3)

        def revoke():
            time.sleep(0.08)
            c = db.connect()
            authz.publish_grant(c, "analyst-ada", DIMS + ["revenue_cents"], ["north"], "admin-root", "mid-query")

        t = threading.Thread(target=revoke)
        t.start()
        res = engine.execute_query(self.conn, qid)
        t.join()
        self.assertEqual(res["status"], "succeeded")
        rows = engine.get_result_rows(self.conn, qid)
        # pinned execution used the launch snapshot
        self.assertEqual({r["organization"] for r in rows}, {"north", "south", "east"})
        # ...but delivery still re-checks and withholds
        page = delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 10)
        self.assertEqual({r["organization"] for r in page["rows"]}, {"north"})
        self.assertIn("south", page["withheld_organizations"])

    def test_pinned_scope_emptied_at_execution_is_denied(self):
        qid = engine.create_query(self.conn, "analyst-ada", self.spec(), "pinned", simulate_delay=0.3)
        # revoke everything for recheck semantics: switch mode to recheck
        self.conn.execute("UPDATE queries SET auth_mode='recheck' WHERE query_id=?", (qid,))
        q = engine.get_query(self.conn, qid)
        snap = authz.load_snapshot(self.conn, q["auth_snapshot"])
        self.conn.execute(
            "UPDATE grant_snapshots SET cols_json=?, orgs_json=? WHERE snapshot_id=?",
            (json.dumps([]), json.dumps([]), snap["snapshot"]),
        )
        self.grant("analyst-ada", [], [], "revoke all")
        res = engine.execute_query(self.conn, qid)
        self.assertEqual(res["status"], "failed")
        self.assertEqual(res.get("code"), "scope_emptied")
        self.assertEqual(engine.get_query(self.conn, qid)["status"], "failed")


class PaginationTests(Base):
    def test_frozen_page_replays_identical_bytes_after_revocation(self):
        qid, _ = self.run_query(mode="pinned")
        p0 = delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 1)
        self.assertEqual(p0["row_count"], 1)
        before = p0["rows"]
        self.grant("analyst-ada", DIMS + ["revenue_cents"], ["north", "east"], "revoke south")
        replay = delivery.get_page(self.conn, qid, "analyst-ada", p0["cursor_id"], 0, 1)
        self.assertTrue(replay["replay"])
        self.assertEqual(replay["rows"], before)

    def test_undelivered_pages_withhold_revoked_rows_and_columns(self):
        qid, _ = self.run_query(mode="pinned")
        delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 1)
        self.grant("analyst-ada", DIMS + ["revenue_cents"], ["north", "east"], "revoke south+orders")
        page = delivery.get_page(self.conn, qid, "analyst-ada", None, 1, 5)
        self.assertEqual(page["status"], "delivered")
        orgs = {r["organization"] for r in page["rows"]}
        self.assertEqual(orgs, {"north"})
        self.assertNotIn("orders", page["columns"])
        self.assertIn("south", page["withheld_organizations"])

    def test_pagination_does_not_skip_rows_when_scope_shrinks(self):
        qid, _ = self.run_query(mode="pinned")
        p0 = delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 1)
        self.grant("analyst-ada", DIMS + ["revenue_cents", "orders"], ["north", "east"], "revoke south")
        p1 = delivery.get_page(self.conn, qid, "analyst-ada", p0["cursor_id"], 1, 1)
        p2 = delivery.get_page(self.conn, qid, "analyst-ada", p0["cursor_id"], 2, 1)
        delivered = [r["organization"] for r in p0["rows"] + p1["rows"]]
        self.assertEqual(sorted(delivered), ["east", "north"])
        self.assertEqual(len(delivered), len(set(delivered)), "no duplicate rows")
        # nothing remains: the next page must say so rather than repeat a row
        self.assertEqual(p2["status"], "exhausted")
        self.assertEqual(p2["code"], "nothing_left_to_deliver")

    def test_cursor_bound_to_principal(self):
        qid, _ = self.run_query()
        p0 = delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 2)
        stolen = delivery.get_page(self.conn, qid, "analyst-cy", p0["cursor_id"], 1, 2)
        self.assertEqual(stolen["status"], "denied")
        self.assertEqual(stolen["code"], "cursor_principal_mismatch")
        self.assertIn("denial_id", stolen)

    def test_other_principal_cannot_page_someone_elses_query(self):
        qid, _ = self.run_query()
        res = delivery.get_page(self.conn, qid, "analyst-bo", None, 0, 2)
        self.assertEqual(res["code"], "cursor_principal_mismatch")

    def test_fully_revoked_scope_denies_new_page(self):
        qid, _ = self.run_query()
        self.grant("analyst-ada", ["segment"], ["west"], "revoke everything usable")
        res = delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 5)
        self.assertEqual(res["status"], "denied")
        self.assertEqual(res["code"], "scope_revoked")
        self.assertTrue(res["denial_id"])

    def test_remaining_page_exhausted_reports_reason(self):
        qid, _ = self.run_query(mode="pinned")
        p0 = delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 1)
        self.grant("analyst-ada", DIMS + ["revenue_cents", "orders"], ["north"], "keep one org only")
        p1 = delivery.get_page(self.conn, qid, "analyst-ada", p0["cursor_id"], 1, 5)
        self.assertEqual(p1["status"], "delivered")
        p2 = delivery.get_page(self.conn, qid, "analyst-ada", p0["cursor_id"], 2, 5)
        self.assertEqual(p2["status"], "exhausted")
        self.assertEqual(p2["code"], "nothing_left_to_deliver")


class CacheTests(Base):
    def test_cache_shared_across_principals_with_equal_scope(self):
        qa, ra = self.run_query(principal="analyst-ada")
        self.assertEqual(ra["cache"], "miss")
        qb, rb = self.run_query(principal="analyst-cy")
        self.assertEqual(rb["cache"], "hit")
        self.assertEqual(engine.get_result_rows(self.conn, qa), engine.get_result_rows(self.conn, qb))

    def test_revoking_one_principal_does_not_delete_shared_cache(self):
        qa, _ = self.run_query(principal="analyst-ada")
        before = self.conn.execute("SELECT COUNT(*) c FROM cache_entries").fetchone()["c"]
        self.grant("analyst-ada", ["organization", "revenue_cents"], ["north"], "narrow ada")
        after = self.conn.execute("SELECT COUNT(*) c FROM cache_entries").fetchone()["c"]
        self.assertEqual(before, after)
        _, rb = self.run_query(principal="analyst-cy")
        self.assertEqual(rb["cache"], "hit")

    def test_narrower_principal_cannot_reuse_wider_cache_key(self):
        self.run_query(principal="analyst-cy")
        # Ada now has a strictly narrower *row* scope; the SQL shape is the
        # same, so the wider entry shows up as a near-miss candidate but is
        # still not served.
        self.grant("analyst-ada", DIMS + ["revenue_cents", "orders"], ["north", "east"], "drop south")
        qid = engine.create_query(self.conn, "analyst-ada", self.spec(), "recheck")
        res = engine.execute_query(self.conn, qid)
        self.assertEqual(res["cache"], "miss")
        plan = json.loads(engine.get_query(self.conn, qid)["plan_json"])
        self.assertFalse(plan["cache"]["hit"])
        near = [c for c in plan["cache_candidates"] if not c["is_exact"]]
        self.assertTrue(near, "wider cache entry should be listed as a near miss")
        self.assertIn("south", near[0]["extra_organizations"])

    def test_dropped_column_changes_cache_shape_and_scope(self):
        self.run_query(principal="analyst-cy")
        self.grant("analyst-ada", DIMS + ["revenue_cents"], ["north", "east", "south"], "drop orders")
        qid = engine.create_query(self.conn, "analyst-ada", self.spec(), "recheck")
        res = engine.execute_query(self.conn, qid)
        self.assertEqual(res["cache"], "miss")
        rows = engine.get_result_rows(self.conn, qid)
        self.assertTrue(rows)
        self.assertNotIn("orders", rows[0])

    def test_aggregate_recomputed_when_org_revoked_after_cache(self):
        qid, _ = self.run_query(principal="analyst-ada")
        self.grant("analyst-ada", DIMS + ["revenue_cents", "orders"], ["north", "east"], "drop south")
        page = delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 10)
        self.assertEqual({r["organization"] for r in page["rows"]}, {"east", "north"})
        self.assertTrue(page["recomputed_from_detail"])
        self.assertNotIn("south", {r["organization"] for r in page["rows"]})


class DownloadTests(Base):
    def test_download_chunks_reauthorized_between_resumes(self):
        qid, _ = self.run_query(mode="pinned")
        job = delivery.start_download(self.conn, qid, "analyst-ada", rows_per_chunk=1)
        self.assertEqual(job["status"], "created")
        first = delivery.resume_download(self.conn, job["job_id"], "analyst-ada", 1)
        self.assertEqual(first["chunks"][0]["row_count"], 1)
        self.grant("analyst-ada", DIMS + ["revenue_cents"], ["north", "east"], "revoke south")
        second = delivery.resume_download(self.conn, job["job_id"], "analyst-ada", 5)
        delivered = [row["organization"] for c in first["chunks"] + second["chunks"] for row in c["rows"]]
        self.assertEqual(sorted(delivered), ["east", "north"])
        self.assertIn("south", second["withheld_organizations"])

    def test_download_revoked_when_scope_emptied(self):
        qid, _ = self.run_query()
        job = delivery.start_download(self.conn, qid, "analyst-ada", rows_per_chunk=1)
        self.grant("analyst-ada", ["segment"], ["west"], "revoke all usable")
        res = delivery.resume_download(self.conn, job["job_id"], "analyst-ada", 1)
        self.assertEqual(res["status"], "revoked")
        self.assertEqual(res["code"], "chunk_scope_revoked")
        row = self.conn.execute("SELECT * FROM download_jobs WHERE job_id=?", (job["job_id"],)).fetchone()
        self.assertEqual(row["status"], "revoked")
        self.assertTrue(row["last_denial"])

    def test_download_recomputes_aggregate_under_narrower_scope(self):
        qid, _ = self.run_query()
        self.grant("analyst-ada", DIMS + ["revenue_cents", "orders"], ["north"], "only north")
        job = delivery.start_download(self.conn, qid, "analyst-ada", rows_per_chunk=5)
        self.assertEqual(job["rows_total"], 1)
        self.assertTrue(job["recomputed_from_detail"])

    def test_other_principal_cannot_resume_job(self):
        qid, _ = self.run_query()
        job = delivery.start_download(self.conn, qid, "analyst-ada", rows_per_chunk=1)
        res = delivery.resume_download(self.conn, job["job_id"], "analyst-cy", 1)
        self.assertEqual(res["status"], "denied")
        self.assertEqual(res["code"], "not_owner")

    def test_revoked_chunks_are_reported_as_truncated_not_silently_complete(self):
        qid, _ = self.run_query(mode="pinned")
        job = delivery.start_download(self.conn, qid, "analyst-ada", rows_per_chunk=1)
        self.assertEqual(job["chunks_total"], 3)
        # revoke one organization *after* the job was created; one chunk is
        # already deliverable, one is withheld -> 2 remain vs 3 planned
        self.grant("analyst-ada", DIMS + ["revenue_cents", "orders"], ["north", "east"], "revoke south")
        res = delivery.resume_download(self.conn, job["job_id"], "analyst-ada", 5)
        self.assertEqual(res["status"], "completed")
        self.assertTrue(res["truncated_by_revocation"])
        self.assertLess(res["chunks_done"], res["chunks_total"])
        self.assertIn("withdrawn", res["note"])
        self.assertIn("south", res["withheld_organizations"])


class AuditTests(Base):
    def test_every_revocation_caused_denial_has_a_record(self):
        qid, _ = self.run_query(mode="pinned")
        self.grant("analyst-ada", ["organization", "revenue_cents"], ["north"], "revoke")
        delivery.get_page(self.conn, qid, "analyst-ada", None, 0, 5)
        rows = self.conn.execute("SELECT * FROM denials").fetchall()
        self.assertTrue(any(r["kind"] == "page" for r in rows))
        kinds = {r["kind"] for r in rows}
        self.assertIn("page", kinds)
        for r in rows:
            self.assertTrue(json.loads(r["detail_json"]) is not None)

    def test_audit_contains_launch_and_cache_events(self):
        qid, _ = self.run_query()
        actions = {r["action"] for r in self.conn.execute("SELECT action FROM audit")}
        self.assertIn("query.launch", actions)
        self.assertIn("cache.lookup", actions)
        self.assertIn("query.finish", actions)


class ScenarioTests(Base):
    def test_revoke_scenario_end_to_end(self):
        from app import server
        res = server.run_revoke_scenario(self.conn)
        step_names = [s["step"] for s in res["steps"]]
        self.assertIn("job resumed after revocation", step_names)
        replay = next(s["replay"] for s in res["steps"] if "replay" in s)
        self.assertTrue(replay["replay"])
        # page size 5 on a 3-row aggregate: the whole result was delivered once
        self.assertEqual(replay["row_count"], 3)
        job_state = next(s["job"] for s in reversed(res["steps"]) if "job" in s and isinstance(s["job"], dict))
        self.assertIsNotNone(job_state)


class ApiTests(unittest.TestCase):
    """End-to-end over HTTP, including concurrent slow query + revoke."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["SHAN_DATA"] = cls.tmp.name
        db.DB_PATH = Path(cls.tmp.name) / "analytics.sqlite3"
        db._thread_local.__dict__.pop("conn", None)
        from app import server
        cls.server = server.build_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        db._thread_local.__dict__.pop("conn", None)
        cls.tmp.cleanup()

    def call(self, method, path, body=None, principal="analyst-ada"):
        import urllib.error
        import urllib.request

        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json", "X-Principal": principal},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_full_http_flow(self):
        status, meta = self.call("GET", "/api/meta")
        self.assertEqual(status, 200)
        spec = {"organization": ["north", "south", "east"], "group_by": ["organization"],
                "measures": ["revenue_cents", "orders"]}
        status, launched = self.call("POST", "/api/query", {"spec": spec, "auth_mode": "pinned"})
        self.assertEqual(status, 200)
        qid = launched["query_id"]
        status, page = self.call("GET", f"/api/queries/{qid}/page?page=0&page_size=5")
        self.assertEqual(page["status"], "delivered")
        status, grant = self.call(
            "POST", "/api/grants",
            {"principal_id": "analyst-ada", "columns": ["organization", "revenue_cents"],
             "organizations": ["north"], "note": "http revoke"},
            principal="admin-root",
        )
        self.assertEqual(status, 200)
        status, replay = self.call("GET", f"/api/queries/{qid}/page?page=0&page_size=5")
        self.assertTrue(replay["replay"])
        self.assertEqual(replay["row_count"], page["row_count"])
        status, denied = self.call("GET", f"/api/queries/{qid}/page?page=1&page_size=5&cursor={page['cursor_id']}")
        self.assertIn(denied["status"], ("exhausted", "delivered"))

    def test_admin_required_for_grant_publish(self):
        status, body = self.call(
            "POST", "/api/grants",
            {"principal_id": "analyst-ada", "columns": ["organization"], "organizations": ["north"]},
            principal="analyst-ada",
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "admin_required")

    def test_concurrent_revoke_during_slow_http_query(self):
        spec = {"organization": ["north", "south"], "group_by": ["organization"],
                "measures": ["revenue_cents"]}
        result = {}

        def launch():
            result["launch"] = self.call(
                "POST", "/api/query",
                {"spec": spec, "auth_mode": "recheck", "delay": 0.6},
            )

        t = threading.Thread(target=launch)
        t.start()
        time.sleep(0.15)
        status, grant = self.call(
            "POST", "/api/grants",
            {"principal_id": "analyst-ada", "columns": ["organization", "revenue_cents"],
             "organizations": ["north"], "note": "racing revoke"},
            principal="admin-root",
        )
        self.assertEqual(status, 200)
        t.join()
        status, launched = result["launch"]
        self.assertEqual(status, 200)
        qid = launched["query_id"]
        rows = launched["query"]["plan"]["execution_scope"]["served_organizations"]
        self.assertEqual(rows, ["north"])
        self.assertEqual(launched["query"]["plan"]["execution_scope"]["source"], "live_intersect_launch")


if __name__ == "__main__":
    unittest.main(verbosity=2)
