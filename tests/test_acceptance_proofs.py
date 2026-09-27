"""Immutable historical proof integrity, independent of current eligibility."""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_support import KernelCase, api_sql, sql_literal
from test_typed_operations import LegacyKernelCase, install_current
from scripts.dev_cluster import DevCluster
from scripts.install import InstallError


class AcceptanceProofTests(KernelCase):
    def verified(self, key="candidate"):
        candidate = self.submit(key)
        claim = self.claim(candidate)
        for check in self.document["checks"]:
            self.record(candidate, claim, check["id"])
        return candidate, claim

    def proof(self, candidate):
        return json.loads(self.cluster.psql(
            "SELECT jsonb_build_object('candidate_id',candidate_id,'generation',generation,"
            "'binding_digest',binding_digest,'proof',proof,'raw',proof::text,'proof_digest',proof_digest) "
            f"FROM hobnail.acceptance_proofs WHERE candidate_id={candidate['candidate_id']}").stdout)

    def insert_receipt(self, candidate, generation, *, binding=None):
        return self.cluster.psql("INSERT INTO hobnail.acceptances(candidate_id,generation,binding_digest,accepted_by) "
            f"VALUES({candidate['candidate_id']},{generation},{sql_literal(binding or candidate['binding_digest'])},'synthetic-kernel-writer')",
            check=False)

    def assert_invalid_receipt(self, candidate, generation, *, binding=None):
        result = self.insert_receipt(candidate, generation, binding=binding)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("INVALID_ACCEPTANCE_PROOF", result.stderr)
        return result

    def raw_result(self, candidate, claim, check_id, *, plugin=None, verifier="independent-verifier", binding=None):
        plugin = plugin or self.plugin_digests["json.equals" if check_id == "metrics" else "json.required_fields"]
        self.cluster.psql("INSERT INTO hobnail.results(candidate_id,generation,check_id,plugin_digest,"
            "binding_digest,verifier,result,detail) VALUES(" + ",".join([
                str(candidate["candidate_id"]), str(claim["generation"]), sql_literal(check_id),
                sql_literal(plugin), sql_literal(binding or candidate["binding_digest"]),
                sql_literal(verifier), "'pass'", "'{}'::jsonb"]) + ")")

    def test_receipt_has_exact_immutable_proof_and_repeated_acceptance_reuses_it(self):
        candidate = self.passing_candidate()
        proof = self.proof(candidate)
        self.assertEqual(proof["proof_digest"], hashlib.sha256(proof["raw"].encode()).hexdigest())
        self.assertEqual(proof["proof"]["binding_digest"], candidate["binding_digest"])
        self.assertEqual(proof["proof"]["binding"]["artifact_digest"], hashlib.sha256(self.content).hexdigest())
        self.assertEqual({row["check_id"] for row in proof["proof"]["checks"]}, {"metrics", "shape"})
        self.assertEqual({row["result"] for row in proof["proof"]["checks"]}, {"pass"})
        self.assertEqual({row["verifier"] for row in proof["proof"]["checks"]}, {"independent-verifier"})
        current = self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})
        self.assertEqual({row["result_id"] for row in proof["proof"]["checks"]}, {row["id"] for row in current["results"]})
        self.ok("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]})
        self.assertEqual(self.proof(candidate), proof)
        counts = self.cluster.psql(f"SELECT count(*) FROM hobnail.acceptances WHERE candidate_id={candidate['candidate_id']}")
        self.assertEqual(counts.stdout.strip(), "2")

    def test_missing_partial_and_nonpass_evidence_refuse_faulty_receipt_writer(self):
        empty = self.submit("empty")
        self.assert_invalid_receipt(empty, 0)
        self.assert_invalid_receipt(empty, 1)
        partial = self.submit("partial")
        claim = self.claim(partial)
        self.record(partial, claim)
        self.assert_invalid_receipt(partial, claim["generation"])
        for outcome in ("fail", "error", "inconclusive"):
            candidate = self.submit(outcome)
            claim = self.claim(candidate)
            self.record(candidate, claim, result=outcome)
            self.record(candidate, claim, "shape")
            self.assert_invalid_receipt(candidate, claim["generation"])
            self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "CHECK_FAILED")
        count = self.cluster.psql("SELECT count(*) FROM hobnail.acceptance_proofs p JOIN hobnail.candidates c "
                                 f"ON c.id=p.candidate_id WHERE c.contract_id={sql_literal(self.cid)}")
        self.assertEqual(count.stdout.strip(), "0")

    def test_wrong_candidate_generation_and_binding_refuse(self):
        candidate, claim = self.verified()
        self.assert_invalid_receipt(candidate, claim["generation"] + 1)
        self.assert_invalid_receipt(candidate, claim["generation"], binding="0" * 64)
        other = self.submit("other")
        self.assert_invalid_receipt(other, claim["generation"], binding=candidate["binding_digest"])
        accepted = self.ok("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]})
        self.assertTrue(accepted["accepted"])

    def test_wrong_plugin_binding_extra_check_and_self_judgment_refuse(self):
        for fault in ("plugin", "binding", "extra", "self", "mixed"):
            candidate = self.submit(fault)
            claim = self.claim(candidate)
            self.raw_result(candidate, claim, "metrics",
                            plugin=self.plugin_digests["json.required_fields"] if fault == "plugin" else None,
                            binding="0" * 64 if fault == "binding" else None,
                            verifier="independent-worker" if fault == "self" else "independent-verifier")
            self.raw_result(candidate, claim, "shape", verifier="other-verifier" if fault == "mixed" else
                            ("independent-worker" if fault == "self" else "independent-verifier"))
            if fault == "extra":
                self.raw_result(candidate, claim, "undeclared")
            self.assert_invalid_receipt(candidate, claim["generation"])

    def test_proofs_are_private_and_immutable_even_for_accidental_owner_writes(self):
        candidate = self.passing_candidate()
        before = self.proof(candidate)
        for role in ("worker", "verifier", "observer"):
            for sql in ("SELECT * FROM hobnail.acceptance_proofs",
                        "SELECT hobnail.acceptance_proof_document(1,1,repeat('0',64))",
                        "SELECT hobnail.require_acceptance_proof()",
                        "DELETE FROM hobnail.acceptance_proofs"):
                result = self.cluster.psql(sql, user=self.logins[role][0], check=False)
                self.assertNotEqual(result.returncode, 0, (role, sql))
        for sql, reason in (("UPDATE hobnail.acceptance_proofs SET proof='{}'", "immutable_record"),
                            ("DELETE FROM hobnail.acceptance_proofs", "immutable_record"),
                            ("TRUNCATE hobnail.acceptance_proofs", "cannot truncate a table referenced in a foreign key constraint")):
            result = self.cluster.psql(sql, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(reason, result.stderr)
        self.assertEqual(self.proof(candidate), before)

    def test_proof_data_and_digest_constraints_bind_direct_inserts(self):
        candidate, claim = self.verified()
        document = json.loads(self.cluster.psql("SELECT hobnail.acceptance_proof_document(" +
            f"{candidate['candidate_id']},{claim['generation']},{sql_literal(candidate['binding_digest'])})").stdout)
        for wrong in ("digest", "identity"):
            changed = copy.deepcopy(document)
            if wrong == "identity":
                changed["candidate_id"] += 1
            literal = sql_literal(json.dumps(changed)) + "::jsonb"
            digest = "repeat('0',64)" if wrong == "digest" else "hobnail.digest(" + literal + ")"
            result = self.cluster.psql("INSERT INTO hobnail.acceptance_proofs VALUES(" +
                f"{candidate['candidate_id']},{claim['generation']},{sql_literal(candidate['binding_digest'])}," +
                literal + "," + digest + ")", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("check constraint", result.stderr)
        self.ok("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]})

    def test_historical_proof_survives_time_source_and_policy_changes(self):
        document = copy.deepcopy(self.document)
        for check in document["checks"]:
            check["max_age_seconds"] = 1
        self.amend(document)
        candidate = self.passing_candidate()
        proof = self.proof(candidate)
        receipts = self.cluster.psql(f"SELECT to_jsonb(a) FROM hobnail.acceptances a WHERE candidate_id={candidate['candidate_id']}").stdout
        self.cluster.psql("SELECT pg_sleep(1.05)")
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "EVIDENCE_STALE")
        self.put_input(2, b'{"orders":3}', expected=self.source["snapshot_id"])
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "INPUT_STALE")
        self.amend(copy.deepcopy(self.document))
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "POLICY_INACTIVE")
        self.assertEqual(self.proof(candidate), proof)
        self.assertEqual(self.cluster.psql(f"SELECT to_jsonb(a) FROM hobnail.acceptances a WHERE candidate_id={candidate['candidate_id']}").stdout, receipts)

    def test_rollback_removes_new_proof_receipt_and_audit_but_preserves_results(self):
        candidate, _ = self.verified()
        cid = candidate["candidate_id"]
        before = self.cluster.psql("SELECT count(*) FROM hobnail.audit").stdout
        result = self.cluster.psql("BEGIN; " + api_sql("candidate.accept", {"candidate_id": cid}) + " ROLLBACK;",
                                   user=self.logins["worker"][0])
        self.assertTrue(json.loads(result.stdout)["ok"])
        self.assertEqual(self.cluster.psql("SELECT count(*) FROM hobnail.audit").stdout, before)
        self.assertEqual(self.cluster.psql(f"SELECT count(*) FROM hobnail.acceptance_proofs WHERE candidate_id={cid}").stdout.strip(), "0")
        self.assertEqual(self.cluster.psql(f"SELECT count(*) FROM hobnail.acceptances WHERE candidate_id={cid}").stdout.strip(), "0")
        self.assertEqual(self.cluster.psql(f"SELECT count(*) FROM hobnail.results WHERE candidate_id={cid}").stdout.strip(), "2")

    def test_concurrent_first_acceptances_share_exactly_one_proof(self):
        candidate, _ = self.verified()
        def accept(_):
            return self.api("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]})
        with ThreadPoolExecutor(max_workers=6) as pool:
            responses = list(pool.map(accept, range(6)))
        self.assertTrue(all(row["ok"] for row in responses), responses)
        cid = candidate["candidate_id"]
        self.assertEqual(self.cluster.psql(f"SELECT count(*) FROM hobnail.acceptance_proofs WHERE candidate_id={cid}").stdout.strip(), "1")
        self.assertEqual(self.cluster.psql(f"SELECT count(*) FROM hobnail.acceptances WHERE candidate_id={cid}").stdout.strip(), "6")


class ProofUpgradeTests(LegacyKernelCase):
    def test_upgrade_preserves_old_receipts_after_freshness_and_identity_changes(self):
        document = copy.deepcopy(self.document)
        for check in document["checks"]:
            check["max_age_seconds"] = 1
        self.amend(document)
        candidate = self.passing_candidate()
        cid = candidate["candidate_id"]
        before_ledger = self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout
        before_receipts = self.cluster.psql(f"SELECT to_jsonb(a) FROM hobnail.acceptances a WHERE candidate_id={cid}").stdout
        before_results = self.cluster.psql(f"SELECT to_jsonb(r) FROM hobnail.results r WHERE candidate_id={cid} ORDER BY id").stdout
        old_generation = json.loads(before_receipts)["generation"]
        self.cluster.psql("SELECT pg_sleep(1.05)")
        self.put_input(2, b'{"orders":3}', expected=self.source["snapshot_id"])
        self.amend(copy.deepcopy(self.document))
        # Historical receipt validation must not depend on today's identity or
        # candidate lease metadata. This is synthetic administrator drift.
        self.cluster.psql("UPDATE hobnail.principals SET enabled=false WHERE principal_id IN "
                          "('independent-verifier','independent-registrar'); "
                          f"UPDATE hobnail.candidates SET generation=generation+1 WHERE id={cid}")
        install_current(self.cluster)
        after_ledger = self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout
        self.assertEqual(len(before_ledger.strip().splitlines()), 4)
        self.assertEqual(len(after_ledger.strip().splitlines()), 6)
        self.assertEqual(after_ledger.strip().splitlines()[:4], before_ledger.strip().splitlines())
        self.assertEqual(self.cluster.psql(f"SELECT to_jsonb(a) FROM hobnail.acceptances a WHERE candidate_id={cid}").stdout, before_receipts)
        self.assertEqual(self.cluster.psql(f"SELECT to_jsonb(r) FROM hobnail.results r WHERE candidate_id={cid} ORDER BY id").stdout, before_results)
        proof = json.loads(self.cluster.psql(f"SELECT to_jsonb(p) FROM hobnail.acceptance_proofs p WHERE candidate_id={cid}").stdout)
        self.assertEqual(proof["generation"], old_generation)
        self.assertEqual({row["verifier"] for row in proof["proof"]["checks"]}, {"independent-verifier"})
        self.denied("worker", "candidate.accept", {"candidate_id": cid}, "POLICY_INACTIVE")
        install_current(self.cluster)
        self.assertEqual(self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout, after_ledger)
        (self.cluster.root / "proof-upgrade.json").write_text(json.dumps({
            "before_ledger": before_ledger, "after_ledger": after_ledger,
            "unchanged_receipts": before_receipts, "unchanged_results": before_results, "backfilled_proof": proof}, indent=2))
        print(f"Historical proof upgrade evidence retained: {self.cluster.root}")


class InvalidProofUpgradeTests(LegacyKernelCase):
    def test_invalid_old_receipt_refuses_upgrade_atomically_without_rewriting_history(self):
        candidate = self.submit()
        self.cluster.psql("INSERT INTO hobnail.acceptances(candidate_id,generation,binding_digest,accepted_by) VALUES(" +
                          f"{candidate['candidate_id']},1,{sql_literal(candidate['binding_digest'])},'synthetic-old-defect')")
        before = self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout
        receipts = self.cluster.psql("SELECT to_jsonb(a) FROM hobnail.acceptances a ORDER BY id").stdout
        server_log = self.cluster.root / "server.log"
        offset = server_log.stat().st_size
        with self.assertRaises(InstallError) as raised:
            install_current(self.cluster)
        # Installer diagnostics are intentionally redacted. Verify the actual
        # PostgreSQL error in the owned server log, not an invented exception API.
        self.assertRegex(server_log.read_bytes()[offset:].decode(), r"(?m)ERROR:\s+INVALID_ACCEPTANCE_PROOF\s*$")
        self.assertEqual(self.cluster.psql("SELECT version,sha256 FROM hobnail.migrations ORDER BY version").stdout, before)
        self.assertEqual(self.cluster.psql("SELECT to_jsonb(a) FROM hobnail.acceptances a ORDER BY id").stdout, receipts)
        self.assertEqual(self.cluster.psql("SELECT to_regclass('hobnail.acceptance_proofs') IS NULL").stdout.strip(), "t")
        self.assertEqual(self.api("worker", "session.get", {})["code"], "UNKNOWN_OPERATION")
        (self.cluster.root / "proof-upgrade-refusal.json").write_text(json.dumps({
            "error": str(raised.exception), "unchanged_ledger": before, "unchanged_invalid_receipts": receipts}, indent=2))
        print(f"Invalid historical proof refusal retained: {self.cluster.root}")


class ProofInstallerGuardsTests(unittest.TestCase):
    def test_installer_refuses_disabled_proof_guards_and_missing_foreign_key(self):
        faults = ["ALTER TABLE hobnail.acceptance_proofs DISABLE TRIGGER immutable",
                  "ALTER TABLE hobnail.acceptances DISABLE TRIGGER acceptance_requires_proof",
                  "ALTER TABLE hobnail.acceptances DROP CONSTRAINT acceptances_proof",
                  "ALTER TABLE hobnail.acceptances DROP CONSTRAINT acceptances_proof; "
                  "ALTER TABLE hobnail.acceptances ADD CONSTRAINT acceptances_proof "
                  "FOREIGN KEY(candidate_id,generation,binding_digest) REFERENCES "
                  "hobnail.acceptance_proofs(candidate_id,generation,binding_digest) NOT ENFORCED",
                  "ALTER TABLE hobnail.acceptance_proofs DROP CONSTRAINT acceptance_proof_digest; "
                  "ALTER TABLE hobnail.acceptance_proofs ADD CONSTRAINT acceptance_proof_digest "
                  "CHECK(hobnail.is_digest(proof_digest) AND proof_digest=hobnail.digest(proof)) NOT ENFORCED",
                  "ALTER TABLE hobnail.acceptance_proofs DROP CONSTRAINT acceptance_proof_digest; "
                  "ALTER TABLE hobnail.acceptance_proofs ADD CONSTRAINT acceptance_proof_digest CHECK(true)"]
        for function in ("RI_FKey_check_ins", "RI_FKey_check_upd", "RI_FKey_noaction_del", "RI_FKey_noaction_upd"):
            faults.append("""DO $fault$ DECLARE entry record; BEGIN
 FOR entry IN SELECT t.tgrelid,t.tgname FROM pg_trigger t
  JOIN pg_constraint c ON c.oid=t.tgconstraint JOIN pg_proc p ON p.oid=t.tgfoid
  WHERE c.conrelid='hobnail.acceptances'::regclass AND c.conname='acceptances_proof'
   AND p.proname=""" + sql_literal(function) + """ LOOP
  EXECUTE format('ALTER TABLE %s DISABLE TRIGGER %I',entry.tgrelid::regclass,entry.tgname);
 END LOOP; END $fault$""")
        for fault in faults:
            with self.subTest(fault=fault):
                cluster = DevCluster()
                try:
                    cluster.start()
                    install_current(cluster)
                    cluster.psql(fault)
                    server_log = cluster.root / "server.log"
                    offset = server_log.stat().st_size
                    with self.assertRaises(InstallError) as raised:
                        install_current(cluster)
                    self.assertRegex(server_log.read_bytes()[offset:].decode(),
                                     r"(?m)ERROR:\s+Hobnail (ledger|acceptance proof(?: check)?) enforcement drift detected\s*$")
                    (cluster.root / "expected-proof-drift.txt").write_text(fault + "\n" + str(raised.exception))
                finally:
                    cluster.stop()


if __name__ == "__main__":
    unittest.main()
