"""Actual all-SCRAM native dispatch, database restore and independent observation.

The caller deliberately discards a real native adapter's completed response.
The service and its measurement surfaces are unchanged. Only a new owned
PostgreSQL cluster, synthetic credentials and a private exact-byte file are used.
The restore remains inside that same cluster; global roles are never dumped.
"""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.dev_cluster import DevCluster
from scripts.install import install
from scripts.local_demo import _bootstrap, _contract, _plugins, GOOD_ARTIFACT, TRUSTED_INPUT
from scripts.qualified_local import configure_endpoints, qualification_probe, secure_admin
from hobnail.audit import Checkpoint, export_verified
from hobnail.client import Client, Connection, PasswordAuthenticationFailed, PsqlTransport, TransportError, canonical_json
from hobnail.deployment import endpoint
from hobnail.verifier import verify_candidate


class NativeRecoveryTests(unittest.TestCase):
    def save(self, name, value):
        path = self.evidence_root / name
        with path.open("x", encoding="utf-8") as stream:
            os.chmod(path, 0o600)
            stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
        return path

    def file_identity(self, path):
        info = path.stat()
        return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
                "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def tool_environment(self, password):
        # No ambient PGOPTIONS, services, passfiles, client certificates or
        # personal configuration are consulted. The only password is generated
        # by secure_admin for this invocation's private cluster.
        return {"LC_ALL": "C", "PGPASSWORD": password, "PGPASSFILE": os.devnull,
                "PGSERVICEFILE": os.devnull, "PGSYSCONFDIR": str(self.tool_home),
                "PGCONNECT_TIMEOUT": "5", "PGSSLMODE": "disable", "PGGSSENCMODE": "disable"}

    def database_tool(self, tool, arguments, name, *, destination=None, password=None):
        password = self.admin.connection.password if password is None else password
        command = [str(self.cluster.bin_dir / tool), "-h", str(self.cluster.socket_dir),
                   "-p", str(self.cluster.port), "-U", "postgres", "-w", *arguments]
        self.assertTrue(all(value not in " ".join(command) for value in self.secret_values),
                        "a generated credential entered an argument")
        result = subprocess.run(command, env=self.tool_environment(password), stdout=destination or subprocess.PIPE,
                                stderr=subprocess.PIPE, text=destination is None, timeout=60, check=False)
        stderr = result.stderr.decode("utf-8") if isinstance(result.stderr, bytes) else result.stderr
        self.assertTrue(all(value not in stderr for value in self.secret_values),
                        "a generated credential entered a tool diagnostic")
        self.save(name + ".json", {"tool": tool, "returncode": result.returncode,
                                   "explicit_generated_password": True, "password_in_arguments": False,
                                   "diagnostic": stderr})
        return result

    def restored_endpoints(self, restored_database, original_endpoints, original_clients, destination):
        root = self.cluster.root / "restored-services"
        root.mkdir(mode=0o700)
        endpoints, clients = {}, {}
        for role, original in original_clients.items():
            directory = root / role
            directory.mkdir(mode=0o700)
            scratch = directory / "scratch"
            scratch.mkdir(mode=0o700)
            config = directory / "connection.json"
            connection = replace(original.transport.connection, database=restored_database)
            transport = PsqlTransport(connection, psql=self.admin.psql)
            clients[role] = Client(transport)
            value = {"role": role, "connection": asdict(connection), "psql": self.admin.psql}
            permission = "write" if role == "adapter" else "read" if role == "observer" else "none"
            if permission != "none":
                value["destination"] = str(destination)
            with config.open("x", encoding="utf-8") as stream:
                os.chmod(config, 0o600)
                stream.write(canonical_json(value))
            endpoints[role] = endpoint(role, config=config, scratch=scratch,
                socket_path=self.cluster.socket_dir / f".s.PGSQL.{self.cluster.port}",
                destination=destination if permission != "none" else None,
                permission=permission, psql=self.admin.psql,
                package_root=original_endpoints[role].policy.script.parent)
        return endpoints, clients

    def test_all_scram_native_restore_reconciles_lost_reply_without_second_write(self):
        self.cluster = DevCluster()
        self.evidence_root = self.cluster.root / "native-recovery-evidence"
        self.evidence_root.mkdir(mode=0o700)
        self.tool_home = self.cluster.root / "empty-tool-config"
        self.tool_home.mkdir(mode=0o700)
        receipt = {"status": "incomplete", "checks": {}, "scope": "native all-SCRAM same-cluster recovery",
                   "cross_cluster_role_recovery": False, "live_project_modified": False}
        provider = None
        leases = []
        stage = "owned_install"
        try:
            self.cluster.start()
            install(f"host={self.cluster.socket_dir} port={self.cluster.port} dbname={self.cluster.database} user=postgres",
                    str(self.cluster.bin_dir / "psql"))
            bootstrap = PsqlTransport(Connection(str(self.cluster.socket_dir), self.cluster.database, "postgres",
                port=self.cluster.port, sslmode="disable"), psql=str(self.cluster.bin_dir / "psql"))
            self.admin = secure_admin(self.cluster, bootstrap)
            cid = "native-recovery"
            clients, provider, leases = _bootstrap(self.cluster, self.admin, [cid])
            self.secret_values = [self.admin.connection.password, *[lease.password.reveal() for lease in leases]]
            destination = self.cluster.root / "published"
            destination.mkdir(mode=0o700)
            target = destination / "accepted.json"
            endpoints = configure_endpoints(self.cluster, clients, destination)
            scoped = {role: item.client() for role, item in endpoints.items()}
            rules = json.loads(self.admin.execute_sql(
                "SELECT json_agg(json_build_object('type',type,'auth_method',auth_method,'error',error)) "
                "FROM pg_hba_file_rules;").strip())
            self.assertEqual(rules, [{"type": "local", "auth_method": "scram-sha-256", "error": None},
                                     {"type": "host", "auth_method": "reject", "error": None}])
            authenticated = []
            for role, native in endpoints.items():
                observed = qualification_probe(native, {})
                self.assertEqual(observed["session_user"], clients[role].transport.connection.user)
                wrong = PsqlTransport(replace(clients[role].transport.connection, password=secrets.token_urlsafe(40)),
                                      psql=self.admin.psql)
                with self.assertRaises(PasswordAuthenticationFailed):
                    wrong.execute_sql("SELECT session_user")
                authenticated.append(role)
            receipt["checks"]["source_native_roles_authenticated"] = sorted(authenticated)
            receipt["checks"]["all_runtime_and_admin_logins_require_scram"] = True

            stage = "actual_validation_and_dispatch"
            plugins = _plugins(scoped["approver"])
            document = _contract("accepted.json", plugins)
            scoped["worker"].require("contract.propose", {"contract_id": cid, "version": 1, "document": document})
            scoped["approver"].require("contract.activate", {"contract_id": cid, "version": 1, "expected_active_version": None})
            trusted = scoped["registrar"].require("input.put", {"contract_id": cid, "source": "orders", "version": 1,
                "content_hex": TRUSTED_INPUT.hex(), "media_type": "application/json", "expected_current": None})["data"]
            artifact = scoped["worker"].require("artifact.put", {"content_hex": GOOD_ARTIFACT.hex(), "media_type": "application/json"})["data"]
            candidate = scoped["worker"].require("candidate.submit", {"contract_id": cid, "artifact_id": artifact["artifact_id"],
                "inputs": {"orders": trusted["snapshot_id"]}, "idempotency_key": "native-recovery-candidate"})["data"]
            accepted = verify_candidate(scoped["verifier"], candidate["candidate_id"])
            self.assertTrue(accepted["ok"], accepted)
            effect_id = scoped["worker"].require("effect.request", {"candidate_id": candidate["candidate_id"],
                "action": "publish", "args": {}, "idempotency_key": "native-recovery-publish"})["data"]["effect_id"]

            def discard_real_caller_reply():
                endpoints["adapter"].dispatch(effect_id)
                raise TransportError("controlled loss after the actual native role returned")

            with self.assertRaises(TransportError):
                discard_real_caller_reply()
            self.assertEqual(target.read_bytes(), GOOD_ARTIFACT)
            original_file = self.file_identity(target)
            effect_before = scoped["worker"].require("effect.get", {"effect_id": effect_id})["data"]
            self.assertEqual(effect_before["state"], "attempted")
            self.assertIsNotNone(effect_before["dispatched_at"])
            self.assertEqual([(row["kind"], row["principal"]) for row in effect_before["reports"]],
                             [("dispatch", "demo-adapter"), ("report", "demo-adapter")])
            candidate_before = scoped["worker"].require("candidate.get", {"candidate_id": candidate["candidate_id"]})["data"]
            self.assertEqual({row["check_id"]: row["result"] for row in candidate_before["results"]},
                             {"metrics": "pass", "shape": "pass"})
            self.assertEqual({row["verifier"] for row in candidate_before["results"]}, {"demo-verifier"})
            budget_before = scoped["worker"].require("budget.get", {"contract_id": cid})["data"]
            self.assertEqual({name: budget_before["budgets"][name]["used"] for name in ("verification", "effects")},
                             {"verification": 1, "effects": 1})
            receipt["checks"]["lost_caller_reply"] = {"injection": "discarded real adapter response after return",
                "server_state": effect_before["state"], "caller_outcome": "unknown", "file": original_file}
            self.save("before-restore.json", {"effect": effect_before, "candidate": candidate_before, "budgets": budget_before})

            stage = "caller_checkpoint_and_actual_dump"
            checkpoint = export_verified(scoped["auditor"], page_size=100).checkpoint
            checkpoint_path = self.save("caller-checkpoint.json", checkpoint.as_dict())
            bad_dump = self.database_tool("pg_dump", ["--schema-only", self.cluster.database], "wrong-password-dump",
                                          password=secrets.token_urlsafe(40))
            self.assertNotEqual(bad_dump.returncode, 0)
            self.assertIn("password authentication failed", bad_dump.stderr)
            archive = self.evidence_root / "hobnail.dump"
            with archive.open("xb") as stream:
                os.chmod(archive, 0o600)
                dumped = self.database_tool("pg_dump", ["--format=custom", self.cluster.database], "dump", destination=stream)
            self.assertEqual(dumped.returncode, 0, "owned pg_dump failed; retained diagnostic")
            self.assertGreater(archive.stat().st_size, 0)
            self.cluster.stop()
            self.assertFalse(self.cluster.is_running())
            self.cluster.start()
            self.assertEqual(self.admin.execute_sql("SELECT session_user").strip(), "postgres")
            receipt["checks"]["owned_postgres_restarted_with_same_scram_roles"] = True

            stage = "new_database_restore"
            restored_database = "hobnail_native_restored"
            self.admin.execute_sql(f'CREATE DATABASE "{restored_database}"')
            restored = self.database_tool("pg_restore", ["--exit-on-error", "--dbname", restored_database, str(archive)], "restore")
            self.assertEqual(restored.returncode, 0, "owned pg_restore failed; retained diagnostic")
            restored_endpoints, restored_clients = self.restored_endpoints(restored_database, endpoints, clients, destination)
            restored_scoped = {role: item.client() for role, item in restored_endpoints.items()}
            for role, native in restored_endpoints.items():
                observed = qualification_probe(native, {})
                self.assertEqual(observed["session_user"], restored_clients[role].transport.connection.user)
            receipt["checks"]["restored_native_roles_authenticated"] = sorted(restored_endpoints)
            anchored = export_verified(restored_scoped["auditor"],
                checkpoint=Checkpoint.from_mapping(json.loads(checkpoint_path.read_text())), page_size=100)
            self.assertEqual(anchored.start, checkpoint)
            self.assertTrue(anchored.externally_anchored)
            self.assertGreater(anchored.checkpoint.sequence, checkpoint.sequence)
            self.save("restored-checkpoint.json", anchored.checkpoint.as_dict())
            effect_restored = restored_scoped["worker"].require("effect.get", {"effect_id": effect_id})["data"]
            self.assertEqual(effect_restored, effect_before)
            budget_restored = restored_scoped["worker"].require("budget.get", {"contract_id": cid})["data"]
            self.assertEqual(budget_restored, budget_before)
            restored_candidate = restored_scoped["worker"].require("candidate.get", {"candidate_id": candidate["candidate_id"]})["data"]
            for key in ("binding_digest", "binding", "artifact", "results", "acceptances"):
                self.assertEqual(restored_candidate[key], candidate_before[key])
            receipt["checks"]["checkpoint_evidence_and_spent_budgets_preserved"] = True

            stage = "refuse_replay_then_observe_existing_file"
            replay = restored_endpoints["adapter"].dispatch(effect_id)
            self.assertFalse(replay["ok"])
            self.assertEqual(replay["code"], "RECONCILIATION_REQUIRED")
            self.assertEqual(self.file_identity(target), original_file)
            for role in ("worker", "observer"):
                probe = qualification_probe(restored_endpoints[role], {"marker": str(target)})
                self.assertIs(probe["marker_write_denied"], True)
                self.assertEqual(self.file_identity(target), original_file)
            observed = restored_endpoints["observer"].observe(effect_id)
            self.assertTrue(observed["ok"], observed)
            self.assertEqual(observed["data"]["state"], "complete")
            self.assertEqual(self.file_identity(target), original_file)
            completed = restored_scoped["worker"].require("effect.get", {"effect_id": effect_id})["data"]
            self.assertEqual([(row["kind"], row["principal"]) for row in completed["reports"]],
                             [("dispatch", "demo-adapter"), ("report", "demo-adapter"), ("observation", "demo-observer")])
            self.assertEqual(completed["reports"][-1]["artifact_digest"], artifact["digest"])
            self.assertEqual(restored_scoped["worker"].require("budget.get", {"contract_id": cid})["data"], budget_before)
            self.assertEqual(scoped["worker"].require("effect.get", {"effect_id": effect_id})["data"]["state"], "attempted")
            receipt["checks"]["reconciliation"] = {"redispatch": replay, "observation": observed,
                "file_identity_unchanged": True, "reports": completed["reports"], "source_database_still_attempted": True}

            stage = "restored_worker_database_privileges"
            # Catch only PostgreSQL insufficient_privilege, not a generic
            # connection failure. The WHERE false target cannot change evidence.
            sql = """BEGIN;
DO $probe$ BEGIN
 BEGIN UPDATE hobnail.results SET result=result WHERE false;
  RAISE EXCEPTION 'protected update unexpectedly allowed';
 EXCEPTION WHEN insufficient_privilege THEN PERFORM set_config('hobnail_native.write_denied','true',true); END;
 BEGIN EXECUTE 'SET ROLE hobnail_owner';
  RAISE EXCEPTION 'owner role unexpectedly allowed';
 EXCEPTION WHEN insufficient_privilege THEN PERFORM set_config('hobnail_native.owner_denied','true',true); END;
END $probe$;
SELECT json_build_object('write_denied',current_setting('hobnail_native.write_denied')::boolean,
 'owner_denied',current_setting('hobnail_native.owner_denied')::boolean,'login',session_user,'database',current_database());
COMMIT;"""
            denied = json.loads(restored_clients["worker"].transport.execute_sql(sql).strip())
            self.assertEqual(denied, {"write_denied": True, "owner_denied": True,
                "login": restored_clients["worker"].transport.connection.user, "database": restored_database})
            receipt["checks"]["restored_worker_sql_privilege_denials"] = {"write_denied": True, "owner_denied": True}
            last_audit = export_verified(restored_scoped["auditor"], checkpoint=anchored.checkpoint, page_size=100)
            self.assertTrue(last_audit.externally_anchored)
            self.save("final-checkpoint.json", last_audit.checkpoint.as_dict())
            self.save("after-reconciliation.json", {"effect": completed, "checkpoint": last_audit.checkpoint.as_dict(),
                "budgets": budget_restored, "file": self.file_identity(target)})

            stage = "credential_exclusion"
            log = (self.cluster.root / "server.log").read_text()
            serialized = canonical_json(receipt)
            self.assertTrue(all(value not in log and value not in serialized for value in self.secret_values),
                            "a generated credential appeared in log/evidence")
            self.assertFalse("SCRAM-SHA-256$4096:" in log, "a verifier appeared in the statement log")
            receipt["checks"]["no_generated_credentials_in_argv_logs_or_receipts"] = True
            receipt["status"] = "passed"
        except Exception as error:
            receipt["status"] = "failed"
            receipt["failure"] = {"stage": stage, "kind": type(error).__name__}
            raise
        finally:
            if provider is not None:
                cleanup = []
                for lease in leases:
                    try:
                        result = provider.revoke(lease.lease_ref)
                        cleanup.append(result.result == "confirmed")
                    except Exception:
                        cleanup.append(False)
                receipt["checks"]["all_runtime_credentials_revoked"] = bool(cleanup) and all(cleanup)
                if not all(cleanup):
                    receipt["status"] = "failed"
            try:
                self.cluster.stop()
                receipt["runtime_stopped"] = not self.cluster.is_running()
            except Exception as error:
                receipt["runtime_stopped"] = False
                receipt["cleanup_failure"] = {"kind": type(error).__name__}
            if receipt["runtime_stopped"] is not True:
                receipt["status"] = "failed"
            self.save("receipt.json", receipt)
            print("Native SCRAM recovery evidence retained:", self.evidence_root)
        self.assertEqual(receipt["status"], "passed", "native recovery cleanup was not confirmed")


if __name__ == "__main__":
    unittest.main()
