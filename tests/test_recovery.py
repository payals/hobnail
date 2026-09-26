"""Real backup/restore and additive installation on owned PostgreSQL 18 only.

The dump and command receipts are retained under each disposable cluster root.
No shared cluster, ambient credentials, original evaluator or expected output
is changed. Restoring into a new database reuses the fixture cluster's existing
role identities: cross-cluster identity/bootstrap recovery is a separate task.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_support import KernelCase, api_sql
from scripts.install import InstallError, install
from hobnail.audit import Checkpoint, export_verified


class RecoveryTests(KernelCase):
    @classmethod
    def tearDownClass(cls):
        print(f"Recovery evidence retained: {cls.cluster.root / 'recovery-evidence'}")
        super().tearDownClass()

    def dsn(self, database=None):
        return (f"host={self.cluster.socket_dir} port={self.cluster.port} "
                f"dbname={database or self.cluster.database} user=postgres")

    def database_api(self, database, role, operation, payload):
        response = self.cluster.psql(api_sql(operation, payload), database=database,
                                    user=self.logins[role][0])
        return json.loads(response.stdout)

    def client(self, database=None):
        outer = self
        class AuditClient:
            def require(self, operation, payload):
                response = outer.database_api(database or outer.cluster.database, "auditor", operation, payload)
                outer.assertTrue(response["ok"], response)
                return response
        return AuditClient()

    def table_snapshot(self, database, schema="hobnail"):
        rows = self.cluster.psql(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            f"WHERE n.nspname='{schema}' AND c.relkind='r' ORDER BY c.relname", database=database)
        snapshot = {}
        for name in rows.stdout.splitlines():
            self.assertRegex(name, r"^[a-z_]+$")
            output = self.cluster.psql(
                f"SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM {schema}.{name} t",
                database=database)
            snapshot[name] = json.loads(output.stdout)
        return snapshot

    def schema_permissions(self, database):
        # pg_dump may restore explicit default function ACLs as NULL. Expand
        # PostgreSQL defaults for functions and relations so the assertion compares
        # effective permissions, including owner-only table defaults.
        output = self.cluster.psql("""
SELECT jsonb_build_object(
 'schema',(SELECT nspacl::text FROM pg_namespace WHERE nspname='hobnail'),
 'relations',(SELECT jsonb_agg(jsonb_build_array(c.relname,c.relkind,pg_get_userbyid(c.relowner),(SELECT jsonb_agg(jsonb_build_array(a.grantee,a.grantor,a.privilege_type,a.is_grantable) ORDER BY a.grantee,a.grantor,a.privilege_type,a.is_grantable) FROM aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 's'::"char" ELSE 'r'::"char" END,c.relowner))) a)) ORDER BY c.relname)
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='hobnail'),
 'functions',(SELECT jsonb_agg(jsonb_build_array(p.proname,pg_get_function_identity_arguments(p.oid),pg_get_userbyid(p.proowner),(SELECT jsonb_agg(jsonb_build_array(a.grantee,a.grantor,a.privilege_type,a.is_grantable) ORDER BY a.grantee,a.grantor,a.privilege_type,a.is_grantable) FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a),p.prosecdef,p.proconfig) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid))
  FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='hobnail'));
""", database=database)
        return json.loads(output.stdout)

    def retained_command(self, tool, arguments, stem):
        directory = self.cluster.root / "recovery-evidence"
        directory.mkdir(exist_ok=True)
        result = subprocess.run([str(self.cluster.bin_dir / tool), *arguments],
                                env=self.cluster._environment(), text=True, capture_output=True,
                                timeout=60, check=False)
        (directory / (stem + ".stdout")).write_text(result.stdout)
        (directory / (stem + ".stderr")).write_text(result.stderr)
        (directory / (stem + ".json")).write_text(json.dumps({"tool": tool, "returncode": result.returncode}))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_dump_restore_preserves_evidence_grants_budgets_and_uncertainty(self):
        candidate = self.passing_candidate()
        reservation = self.ok("worker", "budget.consume", {"contract_id": self.cid, "budget": "research",
                              "units": 3, "idempotency_key": self.cid + ":experiment"})
        effect = self.request_effect(candidate)
        claim = self.claim_effect(effect)
        dispatched = self.dispatch_payload(effect, claim)
        self.ok("adapter", "effect.dispatch", dispatched)
        self.ok("adapter", "effect.report", {**dispatched, "outcome": "uncertain", "receipt": {"lost_reply": True}})
        self.amend(copy.deepcopy(self.document))
        checkpoint = export_verified(self.client(), page_size=7).checkpoint
        expected = self.table_snapshot(self.cluster.database)
        permissions = self.schema_permissions(self.cluster.database)
        directory = self.cluster.root / "recovery-evidence"
        directory.mkdir(exist_ok=True)
        (directory / "caller-checkpoint.json").write_text(json.dumps(checkpoint.as_dict()))
        backup = directory / "hobnail.dump"
        common = ["-h", str(self.cluster.socket_dir), "-p", str(self.cluster.port), "-U", "postgres", "-w"]
        self.retained_command("pg_dump", [*common, "--format=custom", "--file", str(backup), self.cluster.database], "dump")
        restored = "hobnail_restored"
        self.cluster.create_database(restored)
        self.retained_command("pg_restore", [*common, "--exit-on-error", "--dbname", restored, str(backup)], "restore")
        self.assertEqual(self.table_snapshot(restored), expected)
        self.assertEqual(self.schema_permissions(restored), permissions)
        self.assertTrue(install(self.dsn(restored), str(self.cluster.bin_dir / "psql"))["installed"])
        self.assertEqual(self.table_snapshot(restored), expected)
        self.assertEqual(self.schema_permissions(restored), permissions)
        self.assertEqual(self.database_api(restored, "worker", "contract.get", {"contract_id": self.cid})["data"]["version"], 2)
        current = self.database_api(restored, "worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})["data"]
        self.assertFalse(current["eligible"])
        self.assertEqual(len(current["acceptances"]), 1)
        self.assertEqual(len(current["results"]), 2)
        budgets = self.database_api(restored, "worker", "budget.get", {"contract_id": self.cid})["data"]["budgets"]
        self.assertEqual({name: budgets[name]["used"] for name in ("verification", "effects", "research")},
                         {"verification": 1, "effects": 1, "research": 3})
        state = self.database_api(restored, "worker", "effect.get", {"effect_id": effect["effect_id"]})["data"]
        self.assertEqual(state["state"], "uncertain")
        denied = self.database_api(restored, "adapter", "effect.claim", {"effect_id": effect["effect_id"], "lease_seconds": 30})
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["code"], "RECONCILIATION_REQUIRED")
        bypass = self.cluster.psql("UPDATE hobnail.results SET result='pass'", database=restored,
                                   user=self.logins["worker"][0], check=False)
        self.assertNotEqual(bypass.returncode, 0)
        (directory / "restored-write-refusal.stderr").write_text(bypass.stderr)
        report = export_verified(self.client(restored), checkpoint=checkpoint, page_size=2)
        self.assertTrue(report.externally_anchored)
        self.assertGreater(report.checkpoint.sequence, checkpoint.sequence)
        self.assertGreater(reservation["reservation_id"], 0)
        (directory / "restored-checkpoint.json").write_text(json.dumps(report.checkpoint.as_dict()))

    def test_reinstall_and_applied_checksum_mismatch_fail_closed(self):
        before = self.table_snapshot(self.cluster.database)
        result = install(self.dsn(), str(self.cluster.bin_dir / "psql"))
        self.assertTrue(result["installed"])
        self.assertEqual(self.table_snapshot(self.cluster.database), before)
        original = self.cluster.psql("SELECT sha256 FROM hobnail.migrations WHERE version=1").stdout.strip()
        # A controlled alteration of installation metadata in this disposable
        # database proves the installer refuses; source migrations are unchanged.
        self.cluster.psql("UPDATE hobnail.migrations SET sha256=repeat('0',64) WHERE version=1")
        try:
            changed = self.table_snapshot(self.cluster.database)
            with self.assertRaises(InstallError):
                install(self.dsn(), str(self.cluster.bin_dir / "psql"))
            self.assertEqual(self.table_snapshot(self.cluster.database), changed)
        finally:
            self.cluster.psql(f"UPDATE hobnail.migrations SET sha256='{original}' WHERE version=1")
        self.assertTrue(install(self.dsn(), str(self.cluster.bin_dir / "psql"))["installed"])

    def test_legacy_schema_addition_preserves_original_refusal_evaluator(self):
        database = "legacy_additive"
        self.cluster.create_database(database)
        self.cluster.psql_file(ROOT / "install.sql", database=database)
        original = {schema: self.table_snapshot(database, schema) for schema in ("work", "eval")}
        self.assertTrue(install(self.dsn(database), str(self.cluster.bin_dir / "psql"))["installed"])
        self.assertEqual({schema: self.table_snapshot(database, schema) for schema in ("work", "eval")}, original)
        arguments = ["-X", "-e", "-w", "-h", str(self.cluster.socket_dir), "-p", str(self.cluster.port),
                     "-U", "postgres", "-d", database]
        for variable, login in (("owner_uri", "postgres"), ("actor_uri", "actor_role"), ("grader_uri", "grader_role")):
            # psql variables contain nonsecret explicit conninfo, not passwords.
            conninfo = f"host={self.cluster.socket_dir} port={self.cluster.port} dbname={database} user={login} sslmode=disable"
            arguments.extend(["-v", variable + "=" + conninfo])
        arguments.extend(["-f", str(ROOT / "tests" / "scenario.sql")])
        result = subprocess.run([str(self.cluster.bin_dir / "psql"), *arguments], env=self.cluster._environment(),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, check=False)
        evidence = self.cluster.root / "recovery-evidence"
        evidence.mkdir(exist_ok=True)
        (evidence / "legacy-scenario.out").write_text(result.stdout)
        self.assertEqual(result.returncode, 0)
        # Exact original run.sh extraction, with no changed expected assertions.
        selected = []
        pattern = re.compile(r"^(== |ERROR: | assert: .* \| [tf]$|\s*(work|eval)\.[a-z_]+\s+\| [a-z_]+\s+\| [ODRA])")
        for line in result.stdout.splitlines():
            line = re.sub(r"^psql:[^:]+:[0-9]+: ", "", line)
            if pattern.search(line):
                selected.append(line.rstrip())
        actual = "\n".join(selected) + "\n"
        (evidence / "legacy-actual.txt").write_text(actual)
        self.assertEqual(actual, (ROOT / "tests" / "expected.txt").read_text())
        # The scenario itself restores its deliberately disabled trigger.
        self.assertEqual(self.cluster.psql("SELECT tgenabled FROM pg_trigger WHERE tgname='verdicts_immutable'", database=database).stdout.strip(), "O")

    def test_real_audit_pagination_uses_raw_server_bytes_and_fixed_head(self):
        self.denied("worker", "contract.activate", {"contract_id": self.cid, "version": 1,
                                                     "expected_active_version": 1}, "FORBIDDEN")
        before = json.loads(self.cluster.psql("SELECT jsonb_build_object('sequence',seq,'hash',hash) FROM hobnail.audit_head").stdout)
        result = export_verified(self.client(), page_size=1)
        self.assertEqual(result.checkpoint, Checkpoint.from_mapping(before))
        self.assertEqual(result.pages, before["sequence"])
        # Each page appended another event, yet the fixed initial head finished.
        after = int(self.cluster.psql("SELECT seq FROM hobnail.audit_head").stdout)
        self.assertEqual(after, before["sequence"] + result.pages)
