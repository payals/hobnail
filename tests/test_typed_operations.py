"""Typed SQL remains a convenience route through real protocol authority."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from queue import Queue, Empty
import subprocess
import sys
from threading import Thread
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_support import KernelCase, api_sql, sql_literal
from scripts.install import install


def install_current(cluster):
    return install(f"host={cluster.socket_dir} port={cluster.port} dbname={cluster.database} user=postgres",
                   psql=str(cluster.bin_dir / "psql"))


class LegacyKernelCase(KernelCase):
    """Build the actual unchanged 001-004 schema, then exercise the new installer.

    The historical baseline does not run today's post-install proof guards.
    Its ledger hashes describe SQL actually executed in this owned cluster.
    """
    @classmethod
    def setUpClass(cls):
        def baseline_install(_dsn, psql):
            statements = ["BEGIN", "CREATE ROLE hobnail_owner NOLOGIN NOSUPERUSER NOCREATEDB "
                          "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
                          f'GRANT CREATE ON DATABASE "{cls.cluster.database}" TO hobnail_owner',
                          "SET LOCAL ROLE hobnail_owner"]
            files = sorted((ROOT / "migrations").glob("*.sql"))[:4]
            if [int(path.name[:3]) for path in files] != [1, 2, 3, 4]:
                raise AssertionError("historical baseline migrations are missing")
            for version, path in enumerate(files, 1):
                statements.append(path.read_text())
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                statements.append(f"INSERT INTO hobnail.migrations(version,sha256) VALUES({version},'{digest}')")
            statements.extend(["RESET ROLE", f'REVOKE CREATE ON DATABASE "{cls.cluster.database}" FROM hobnail_owner',
                               "COMMIT"])
            cls.cluster.psql(";\n".join(statements))
            rows = cls.cluster.psql("SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM hobnail.migrations m")
            return {"installed": True, "protocol": 1, "migrations": json.loads(rows.stdout)}
        with patch("scripts.install.install", side_effect=baseline_install):
            super().setUpClass()


class SqlSession:
    """One bounded psql backend, kept alive while a second connection upgrades."""
    def __init__(self, cluster, login):
        self.lines = Queue()
        self.process = subprocess.Popen(
            [str(cluster.bin_dir / "psql"), *cluster._psql_arguments(login, None)],
            env=cluster._environment(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        def read():
            for line in self.process.stdout:
                self.lines.put(line.rstrip("\n"))
            self.lines.put(None)
        self.reader = Thread(target=read, daemon=True)
        self.reader.start()
        self.query("SET statement_timeout='5s';")

    def query(self, sql):
        self.process.stdin.write(sql + "\n\\echo HOBNAIL_QUERY_END\n")
        self.process.stdin.flush()
        output = []
        while True:
            try:
                line = self.lines.get(timeout=10)
            except Empty:
                raise AssertionError("owned SQL session did not finish within ten seconds") from None
            if line is None:
                raise AssertionError("owned SQL session ended: " + self.process.stderr.read())
            if line == "HOBNAIL_QUERY_END":
                return output
            if line:
                output.append(line)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write("\\q\n")
            self.process.stdin.flush()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
        self.reader.join(timeout=5)


class TypedOperationsTests(KernelCase):
    def typed(self, role, sql):
        response = json.loads(self.cluster.psql("SELECT " + sql, user=self.logins[role][0]).stdout)
        self.assertIs(type(response["ok"]), bool)
        self.assertIs(type(response["event_id"]), int)
        self.assertGreater(response["event_id"], 0)
        return response

    def test_session_identity_is_authenticated_and_payload_cannot_assert_it(self):
        for role in ("worker", "verifier", "registrar"):
            result = self.typed(role, "hobnail.session_get()")
            self.assertTrue(result["ok"], result)
            self.assertEqual(set(result["data"]), {"principal_id", "role", "contracts", "valid_until"})
            self.assertEqual(result["data"]["principal_id"], self.logins[role][1])
            self.assertEqual(result["data"]["role"], role)
            self.assertIn(self.cid, result["data"]["contracts"])
            self.assertIsNone(result["data"]["valid_until"])
        self.denied("worker", "session.get", {"principal_id": "independent-verifier"}, "INVALID_REQUEST")
        unknown = self.raw_api("accept_unknown", "session.get", {})
        self.assertEqual(unknown["code"], "UNAUTHENTICATED")

    def test_session_expiry_and_role_memberships_still_refuse(self):
        for login in ("typed_expired", "typed_member"):
            self.cluster.psql(f"CREATE ROLE {login} LOGIN")
            bound = self.raw_api("postgres", "principal.bind", {
                "login": login, "principal": login, "role": "worker",
                "contracts": [self.cid], "sources": [], "profiles": []})
            self.assertTrue(bound["ok"], bound)
        self.cluster.psql("UPDATE hobnail.principals SET valid_until=clock_timestamp()-interval '1 second' "
                          "WHERE login='typed_expired'; CREATE ROLE typed_group NOLOGIN; "
                          "GRANT typed_group TO typed_member")
        self.assertEqual(self.raw_api("typed_expired", "session.get", {})["code"], "UNAUTHENTICATED")
        self.assertEqual(self.raw_api("typed_member", "session.get", {})["code"], "FORBIDDEN")

    def test_typed_lifecycle_preserves_generic_replay_and_independent_verdict(self):
        art = self.typed("worker", "hobnail.artifact_put(decode(" + sql_literal(self.content.hex())
                         + ",'hex'),'application/json')")
        self.assertTrue(art["ok"], art)
        payload = self.submission(artifact=art["data"])
        sql = "hobnail.candidate_submit(%s,%s,%s::jsonb,%s)" % (
            sql_literal(self.cid), payload["artifact_id"], sql_literal(json.dumps(payload["inputs"])),
            sql_literal(payload["idempotency_key"]))
        submitted = self.typed("worker", sql)
        self.assertTrue(submitted["ok"], submitted)
        generic = self.api("worker", "candidate.submit", payload)
        self.assertEqual(submitted["data"], generic["data"])
        self.assertNotEqual(submitted["event_id"], generic["event_id"])
        candidate = submitted["data"]
        cid = candidate["candidate_id"]
        worker_claim = self.typed("worker", f"hobnail.verification_claim({cid})")
        self.assertEqual(worker_claim["code"], "FORBIDDEN")
        claimed = self.typed("verifier", f"hobnail.verification_claim({cid})")
        self.assertTrue(claimed["ok"], claimed)
        for check in self.document["checks"]:
            data = self.result_payload(candidate, claimed["data"], check["id"])
            args = [str(cid), sql_literal(data["token"]) + "::uuid", str(data["generation"])]
            args.extend(sql_literal(data[key]) for key in ("binding_digest", "check_id", "plugin_digest", "result"))
            args.append(sql_literal(json.dumps(data["detail"])) + "::jsonb")
            recorded = self.typed("verifier", "hobnail.verification_record(" + ",".join(args) + ")")
            self.assertTrue(recorded["ok"], recorded)
        accepted = self.typed("worker", f"hobnail.candidate_accept({cid})")
        self.assertTrue(accepted["ok"], accepted)
        current = self.typed("worker", f"hobnail.candidate_get({cid})")
        self.assertTrue(current["data"]["eligible"])
        key = self.cid + ":effect"
        effect = self.typed("worker", f"hobnail.effect_request({cid},'publish','{{}}'::jsonb,{sql_literal(key)})")
        self.assertTrue(effect["ok"], effect)
        replay = self.ok("worker", "effect.request", {"candidate_id": cid, "action": "publish", "args": {}, "idempotency_key": key})
        self.assertEqual(effect["data"], replay)
        eid = effect["data"]["effect_id"]
        self.assertEqual(self.typed("worker", f"hobnail.effect_get({eid})")["data"]["state"], "reserved")
        self.assertEqual(self.typed("worker", f"hobnail.effect_cancel({eid})")["data"]["state"], "cancelled")

    def test_typed_contract_proposal_does_not_activate_it(self):
        proposed = self.typed("worker", "hobnail.contract_propose(" + sql_literal(self.cid)
                              + ",2," + sql_literal(json.dumps(self.document)) + "::jsonb)")
        self.assertTrue(proposed["ok"], proposed)
        inactive = self.ok("worker", "contract.get", {"contract_id": self.cid, "version": 2})
        self.assertFalse(inactive["active"])
        self.assertEqual(inactive["approvals"], [])
        self.assertEqual(inactive["policy_digest"], proposed["data"]["policy_digest"])
        self.assertEqual(self.ok("worker", "contract.get", {"contract_id": self.cid})["version"], 1)
        self.denied("worker", "contract.activate", {"contract_id": self.cid, "version": 2,
                                                     "expected_active_version": 1}, "FORBIDDEN")

    def test_required_nulls_reach_audit_but_sql_cast_errors_do_not(self):
        for sql in ("hobnail.candidate_get(NULL::bigint)",
                    "hobnail.artifact_put(NULL::bytea,'application/json')",
                    "hobnail.contract_propose(NULL::text,1,'{}'::jsonb)",
                    "hobnail.verification_claim(1,NULL::integer)"):
            role = "verifier" if "verification_claim" in sql else "worker"
            result = self.typed(role, sql)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["code"], "INVALID_REQUEST")
            audit = self.cluster.psql(f"SELECT event->>'operation' FROM hobnail.audit WHERE seq={result['event_id']}")
            self.assertTrue(audit.stdout.strip())
        before = self.cluster.psql("SELECT count(*) FROM hobnail.audit").stdout
        failed = self.cluster.psql("SELECT hobnail.candidate_get('not-an-integer'::bigint)",
                                   user=self.logins["worker"][0], check=False)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.cluster.psql("SELECT count(*) FROM hobnail.audit").stdout, before)

    def test_fixed_facade_cannot_expose_internal_authority(self):
        for function in ("dispatch", "dispatch_protocol_1"):
            failed = self.cluster.psql(f"SELECT hobnail.{function}('session.get','{{}}'::jsonb,NULL)",
                                       user=self.logins["worker"][0], check=False)
            self.assertNotEqual(failed.returncode, 0)
        names = ["session_get", "contract_propose", "artifact_put", "candidate_submit", "candidate_get",
                 "verification_claim", "verification_record", "candidate_accept", "budget_get", "budget_consume",
                 "effect_request", "effect_get", "effect_cancel"]
        rows = json.loads(self.cluster.psql("SELECT jsonb_agg(jsonb_build_object('name',p.proname,"
            "'definer',p.prosecdef,'strict',p.proisstrict,'config',p.proconfig,'allowed',"
            "has_function_privilege('accept_worker',p.oid,'EXECUTE'))) FROM pg_proc p JOIN pg_namespace n "
            "ON n.oid=p.pronamespace WHERE n.nspname='hobnail' AND p.proname IN ("
            + ",".join(sql_literal(name) for name in names) + ")").stdout)
        self.assertEqual({row["name"] for row in rows}, set(names))
        for row in rows:
            self.assertFalse(row["definer"], row)
            self.assertFalse(row["strict"], row)
            self.assertTrue(row["allowed"], row)
            self.assertIn("search_path=pg_catalog, hobnail, pg_temp", row["config"])

    def test_concurrent_generic_and_typed_replay_consume_once(self):
        payload = {"contract_id": self.cid, "budget": "research", "units": 1, "idempotency_key": self.cid + ":mixed"}
        sql = "hobnail.budget_consume(%s,'research',1,%s)" % (sql_literal(self.cid), sql_literal(payload["idempotency_key"]))
        def consume(index):
            return self.typed("worker", sql) if index % 2 else self.api("worker", "budget.consume", payload)
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(consume, range(6)))
        self.assertTrue(all(row["ok"] for row in results), results)
        self.assertEqual(len({row["data"]["reservation_id"] for row in results}), 1)
        budget = self.typed("worker", "hobnail.budget_get(" + sql_literal(self.cid) + ")")
        self.assertEqual(budget["data"]["budgets"]["research"]["used"], 1)


class TypedUpgradeTests(LegacyKernelCase):
    def test_connected_backend_observes_additive_upgrade_and_old_operations(self):
        before = self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout
        self.assertEqual(len(before.strip().splitlines()), 4)
        session = SqlSession(self.cluster, self.logins["worker"][0])
        self.addCleanup(session.close)
        pid = session.query("SELECT pg_backend_pid();")[0]
        session.query("PREPARE old_api(text,jsonb) AS SELECT hobnail.api($1,$2);")
        previous = json.loads(session.query("EXECUTE old_api('session.get','{}');")[0])
        self.assertEqual(previous["code"], "UNKNOWN_OPERATION")
        budget_sql = "EXECUTE old_api('budget.get',%s::jsonb);" % sql_literal(json.dumps({"contract_id": self.cid}))
        old_budget = json.loads(session.query(budget_sql)[0])["data"]
        upgraded = install_current(self.cluster)
        self.assertEqual([row["version"] for row in upgraded["migrations"]], list(range(1, 7)))
        after = self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout
        self.assertEqual(after.strip().splitlines()[:4], before.strip().splitlines())
        self.assertEqual(session.query("SELECT pg_backend_pid();")[0], pid)
        current = json.loads(session.query("EXECUTE old_api('session.get','{}');")[0])
        self.assertTrue(current["ok"], current)
        self.assertEqual(current["data"]["role"], "worker")
        self.assertEqual(json.loads(session.query("SELECT hobnail.session_get();")[0])["data"], current["data"])
        self.assertEqual(json.loads(session.query(budget_sql)[0])["data"], old_budget)
        (self.cluster.root / "typed-upgrade.json").write_text(json.dumps({
            "before_ledger": before, "after_ledger": after, "same_backend_pid": int(pid),
            "before_session": previous, "after_session": current}, indent=2))
        print(f"Typed upgrade evidence retained: {self.cluster.root}")


if __name__ == "__main__":
    unittest.main()
