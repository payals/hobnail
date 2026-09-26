"""Frozen protocol-1 acceptance cases exercised through real SQL identities.

No mocks, SET ROLE impersonation, evaluator edits or live database are used.
The controlled file consequence is real; socket-trust test logins do not imply
OS isolation, vault qualification or autonomous project outcomes.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kernel_support import KernelCase, api_sql


class KernelAcceptanceTests(KernelCase):
    def test_real_logins_cannot_bypass_protected_tables_or_roles(self):
        for role in ("worker", "rotated", "registrar", "verifier", "approver", "adapter", "observer"):
            login = self.logins[role][0]
            with self.subTest(role=role):
                self.assertEqual(self.cluster.psql("SELECT session_user", user=login).stdout.strip(), login)
                for sql in (
                    "INSERT INTO hobnail.audit(seq,event,previous_hash,hash) VALUES (999999,'{}','x','x')",
                    "UPDATE hobnail.results SET result='pass'",
                    "DELETE FROM hobnail.reservations",
                    "TRUNCATE hobnail.audit",
                    "SELECT nextval(pg_get_serial_sequence('hobnail.results','id'))",
                    "UPDATE hobnail.contracts SET version=999",
                    "ALTER TABLE hobnail.results DISABLE TRIGGER ALL",
                    "SET ROLE hobnail_owner",
                    "SET ROLE accept_verifier" if role != "verifier" else "SET ROLE accept_worker",
                    "CREATE ROLE illicit_superuser SUPERUSER",
                    "SELECT hobnail.dispatch('candidate.accept','{}',NULL)",
                ):
                    denied = self.cluster.psql(sql, user=login, check=False)
                    self.assertNotEqual(denied.returncode, 0, (role, sql))

    def test_worker_cannot_bind_activate_register_or_forge_verdict(self):
        candidate = self.submit()
        claim = self.claim(candidate)
        self.denied("worker", "verification.record", self.result_payload(candidate, claim), "FORBIDDEN")
        self.denied("worker", "verification.claim", {"candidate_id": candidate["candidate_id"], "lease_seconds": 60}, "FORBIDDEN")
        self.denied("worker", "contract.activate", {"contract_id": self.cid, "version": 1,
                                                     "expected_active_version": 1}, "FORBIDDEN")
        self.denied("worker", "plugin.register", {"plugin_id": "json.equals", "version": 2,
                                                   "kind": "validator", "manifest": {}}, "FORBIDDEN")
        self.denied("worker", "principal.bind", {"login": "accept_worker", "principal": "fake",
                                                  "role": "approver", "contracts": [self.cid],
                                                  "sources": [], "profiles": []}, "FORBIDDEN")

    def test_exact_bytes_complete_evidence_and_historical_receipt(self):
        candidate = self.passing_candidate()
        result = self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})
        self.assertTrue(result["eligible"])
        self.assertEqual(result["binding_digest"], candidate["binding_digest"])
        self.assertEqual(result["binding"]["artifact_digest"], hashlib.sha256(self.content).hexdigest())
        self.assertEqual(result["artifact"]["content_hex"], self.content.hex())
        self.assertEqual({row["check_id"] for row in result["results"]}, {"metrics", "shape"})
        self.assertEqual({row["result"] for row in result["results"]}, {"pass"})
        self.assertEqual(len(result["acceptances"]), 1)

    def test_fail_error_and_inconclusive_each_refuse_and_remain_immutable(self):
        for outcome in ("fail", "error", "inconclusive"):
            with self.subTest(outcome=outcome):
                candidate = self.submit(outcome)
                claim = self.claim(candidate)
                self.record(candidate, claim, result=outcome)
                self.record(candidate, claim, "shape")
                self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "CHECK_FAILED")
                self.denied("verifier", "verification.record", self.result_payload(candidate, claim), "ALREADY_RECORDED")
                self.denied("verifier", "verification.claim", {"candidate_id": candidate["candidate_id"], "lease_seconds": 60})
                current = self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})
                self.assertFalse(current["eligible"])
                self.assertEqual([row["result"] for row in current["results"]], [outcome, "pass"])
                self.assertEqual(current["acceptances"], [])

    def test_missing_unknown_and_duplicate_checks_do_not_accept(self):
        candidate = self.submit()
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "MISSING_CHECKS")
        claim = self.claim(candidate)
        self.record(candidate, claim)
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "MISSING_CHECKS")
        unknown = self.result_payload(candidate, claim)
        unknown["check_id"] = "invented"
        self.denied("verifier", "verification.record", unknown, "INVALID_REQUEST")
        self.denied("verifier", "verification.record", self.result_payload(candidate, claim), "ALREADY_RECORDED")
        self.record(candidate, claim, "shape")
        self.ok("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]})

    def test_changed_artifact_cannot_reuse_binding_or_other_worker_artifact(self):
        old = self.passing_candidate("old")
        changed = self.put_artifact(b'{"orders":999,"period":"2026-09"}')
        candidate = self.submit("new", changed)
        self.assertNotEqual(old["binding_digest"], candidate["binding_digest"])
        claim = self.claim(candidate)
        payload = self.result_payload(candidate, claim)
        payload["binding_digest"] = old["binding_digest"]
        self.denied("verifier", "verification.record", payload, "BINDING_MISMATCH")
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "MISSING_CHECKS")
        foreign = self.put_artifact(self.content, "other_worker")
        self.denied("worker", "candidate.submit", self.submission("foreign", foreign), "FORBIDDEN")
        wrong_type = self.put_artifact(self.content, media_type="text/plain")
        self.denied("worker", "candidate.submit", self.submission("type", wrong_type), "ARTIFACT_MISMATCH")

    def test_source_advance_invalidates_acceptance_and_reserved_dispatch(self):
        candidate = self.passing_candidate()
        effect = self.request_effect(candidate)
        claim = self.claim_effect(effect)
        self.put_input(2, b'{"orders":3}', expected=self.source["snapshot_id"])
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "INPUT_STALE")
        self.denied("adapter", "effect.dispatch", self.dispatch_payload(effect, claim), "INPUT_STALE")
        current = self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})
        self.assertFalse(current["eligible"])
        self.assertEqual(len(current["acceptances"]), 1)
        self.denied("worker", "candidate.submit", self.submission("stale"), "INPUT_STALE")

    def test_policy_advance_invalidates_acceptance_and_reserved_dispatch(self):
        candidate = self.passing_candidate()
        effect = self.request_effect(candidate)
        claim = self.claim_effect(effect)
        self.amend(copy.deepcopy(self.document))
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "POLICY_INACTIVE")
        self.denied("adapter", "effect.dispatch", self.dispatch_payload(effect, claim), "POLICY_INACTIVE")
        current = self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})
        self.assertFalse(current["eligible"])
        self.assertEqual(len(current["acceptances"]), 1)
        budgets = self.ok("worker", "budget.get", {"contract_id": self.cid})["budgets"]
        self.assertEqual(budgets["verification"]["used"], 1)
        self.assertEqual(budgets["effects"]["used"], 1)

    def test_wrong_plugin_manifest_refuses(self):
        candidate = self.submit()
        claim = self.claim(candidate)
        payload = self.result_payload(candidate, claim)
        payload["plugin_digest"] = self.plugin_digests["json.required_fields"]
        self.denied("verifier", "verification.record", payload, "PLUGIN_MISMATCH")
        doc = copy.deepcopy(self.document)
        doc["checks"][0]["plugin_digest"] = "0" * 64
        response = self.api("worker", "contract.propose", {"contract_id": self.cid, "version": 2, "document": doc})
        if response["ok"]:
            self.denied("approver", "contract.activate", {"contract_id": self.cid, "version": 2,
                                                           "expected_active_version": 1}, "PLUGIN_MISMATCH")
        else:
            self.assertEqual(response["code"], "PLUGIN_MISMATCH")

    def test_expired_generation_is_fenced_and_results_cannot_be_combined(self):
        candidate = self.submit()
        old = self.claim(candidate, seconds=1)
        self.record(candidate, old)
        self.cluster.psql("SELECT pg_sleep(1.15)")
        new = self.claim(candidate)
        self.assertGreater(new["generation"], old["generation"])
        self.denied("verifier", "verification.record", self.result_payload(candidate, old, "shape"), "LEASE_MISMATCH")
        self.record(candidate, new, "shape")
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "MISSING_CHECKS")
        self.record(candidate, new)
        self.ok("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]})
        rows = self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})["results"]
        self.assertEqual(len(rows), 3)
        self.assertEqual(self.ok("worker", "budget.get", {"contract_id": self.cid})["budgets"]["verification"]["used"], 2)

    def test_verifier_lease_uses_wall_clock_inside_long_transaction(self):
        candidate = self.submit()
        claim = self.claim(candidate, seconds=1)
        sql = "BEGIN; SELECT pg_sleep(1.15); " + api_sql("verification.record", self.result_payload(candidate, claim)) + " COMMIT;"
        result = self.cluster.psql(sql, user=self.logins["verifier"][0])
        response = json.loads(next(line for line in result.stdout.splitlines() if line.startswith("{")))
        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "LEASE_EXPIRED")
        self.assertEqual(self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})["results"], [])

    def test_evidence_expiry_is_current_and_history_remains(self):
        document = copy.deepcopy(self.document)
        for check in document["checks"]:
            check["max_age_seconds"] = 1
        self.amend(document)
        candidate = self.passing_candidate()
        self.cluster.psql("SELECT pg_sleep(1.15)")
        self.denied("worker", "candidate.accept", {"candidate_id": candidate["candidate_id"]}, "EVIDENCE_STALE")
        current = self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})
        self.assertFalse(current["eligible"])
        self.assertEqual(len(current["acceptances"]), 1)

    def test_rotated_stable_principal_cannot_verify_or_register_own_inputs(self):
        doc = copy.deepcopy(self.document)
        doc["access"]["verifiers"].append("independent-worker")
        doc["sources"][0]["registrars"].append("independent-worker")
        self.amend(doc)
        candidate = self.submit()
        self.denied("self_verifier", "verification.claim", {"candidate_id": candidate["candidate_id"],
                                                           "lease_seconds": 60}, "SELF_JUDGING")
        own_input = self.put_input(2, self.content, expected=self.source["snapshot_id"], role="self_registrar")
        self.denied("worker", "candidate.submit", self.submission("self-input", source=own_input), "SELF_JUDGING")

    def test_unknown_identity_and_out_of_scope_contract_refuse(self):
        response = self.raw_api("accept_unknown", "contract.get", {"contract_id": self.cid})
        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "UNAUTHENTICATED")
        self.denied("worker", "contract.propose", {"contract_id": "not-authorized", "version": 1,
                                                    "document": self.document}, "SCOPE_MISMATCH")
        missing = self.submission()
        missing["inputs"] = {}
        self.denied("worker", "candidate.submit", missing, "INPUT_MISMATCH")
        invented = self.submission()
        invented["inputs"]["orders"] = 999999999
        self.denied("worker", "candidate.submit", invented, "INPUT_MISMATCH")

    def test_submission_idempotence_binds_arguments_and_rotated_principal(self):
        payload = self.submission()
        original = self.ok("worker", "candidate.submit", payload)
        replay = self.ok("rotated", "candidate.submit", payload)
        self.assertEqual(replay, original)
        changed = self.put_artifact(b'{"orders":3}')
        payload["artifact_id"] = changed["artifact_id"]
        self.denied("rotated", "candidate.submit", payload, "IDEMPOTENCY_CONFLICT")

    def test_budget_idempotence_and_policy_lineage_never_reset_consumption(self):
        payload = {"contract_id": self.cid, "budget": "research", "units": 7,
                   "idempotency_key": self.cid + ":reservation"}
        reserved = self.ok("worker", "budget.consume", payload)
        self.assertEqual(self.ok("rotated", "budget.consume", payload), reserved)
        self.denied("worker", "budget.consume", dict(payload, units=6), "IDEMPOTENCY_CONFLICT")
        doc = copy.deepcopy(self.document)
        doc["budgets"]["research"] = 5
        self.amend(doc)
        budget = self.ok("worker", "budget.get", {"contract_id": self.cid})["budgets"]["research"]
        self.assertEqual(budget, {"cap": 5, "used": 7, "remaining": 0})
        self.denied("worker", "budget.consume", dict(payload, units=1, idempotency_key=self.cid + ":new"), "BUDGET_EXHAUSTED")
        for category in ("verification", "effects"):
            self.denied("worker", "budget.consume", dict(payload, budget=category, units=1,
                                                           idempotency_key=self.cid + ":" + category), "FORBIDDEN")

    def test_concurrent_budget_consumption_cannot_exceed_cap(self):
        doc = copy.deepcopy(self.document)
        doc["budgets"]["research"] = 3
        self.amend(doc)
        def consume(number):
            return self.raw_api(self.logins["worker"][0], "budget.consume",
                                {"contract_id": self.cid, "budget": "research", "units": 1,
                                 "idempotency_key": self.cid + ":" + str(number)})
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(consume, range(8)))
        self.assertEqual(sum(value["ok"] for value in outcomes), 3, outcomes)
        self.assertEqual([value["code"] for value in outcomes if not value["ok"]], ["BUDGET_EXHAUSTED"] * 5)
        self.assertEqual(self.ok("worker", "budget.get", {"contract_id": self.cid})["budgets"]["research"]["used"], 3)

    def test_concurrent_identical_requests_reserve_once(self):
        payload = {"contract_id": self.cid, "budget": "research", "units": 1,
                   "idempotency_key": self.cid + ":same"}
        def consume(_):
            return self.raw_api(self.logins["worker"][0], "budget.consume", payload)
        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(consume, range(6)))
        self.assertTrue(all(value["ok"] for value in outcomes), outcomes)
        self.assertEqual(len({value["data"]["reservation_id"] for value in outcomes}), 1)
        self.assertEqual(self.ok("worker", "budget.get", {"contract_id": self.cid})["budgets"]["research"]["used"], 1)

    def test_source_update_and_admission_have_one_serial_order(self):
        candidate = self.passing_candidate()
        payload = {"contract_id": self.cid, "source": "orders", "version": 2,
                   "content_hex": b'{"orders":3}'.hex(), "media_type": "application/json",
                   "expected_current": self.source["snapshot_id"]}
        with ThreadPoolExecutor(max_workers=2) as pool:
            admission = pool.submit(self.raw_api, self.logins["worker"][0], "candidate.accept", {"candidate_id": candidate["candidate_id"]})
            update = pool.submit(self.raw_api, self.logins["registrar"][0], "input.put", payload)
            accepted, updated = admission.result(), update.result()
        self.assertTrue(updated["ok"], updated)
        if accepted["ok"]:
            self.assertLess(accepted["event_id"], updated["event_id"])
        else:
            self.assertEqual(accepted["code"], "INPUT_STALE")
            self.assertGreater(accepted["event_id"], updated["event_id"])
        self.assertFalse(self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})["eligible"])

    def test_competing_source_compare_and_swap_installs_one_snapshot(self):
        def update(version):
            return self.raw_api(self.logins["registrar"][0], "input.put",
                                {"contract_id": self.cid, "source": "orders", "version": version,
                                 "content_hex": json.dumps({"orders": version}).encode().hex(),
                                 "media_type": "application/json", "expected_current": self.source["snapshot_id"]})
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(update, (2, 3)))
        winners = [row for row in outcomes if row["ok"]]
        losers = [row for row in outcomes if not row["ok"]]
        self.assertEqual(len(winners), 1, outcomes)
        self.assertEqual(len(losers), 1, outcomes)
        self.assertEqual(losers[0]["code"], "VERSION_CONFLICT")
        candidate = self.submit(source=winners[0]["data"])
        current = self.ok("worker", "candidate.get", {"candidate_id": candidate["candidate_id"]})
        self.assertEqual(current["binding"]["inputs"]["orders"]["snapshot_id"], winners[0]["data"]["snapshot_id"])

    def test_policy_activation_and_dispatch_have_one_serial_order(self):
        candidate = self.passing_candidate()
        effect = self.request_effect(candidate)
        claim = self.claim_effect(effect)
        self.ok("worker", "contract.propose", {"contract_id": self.cid, "version": 2, "document": self.document})
        with ThreadPoolExecutor(max_workers=2) as pool:
            dispatch = pool.submit(self.raw_api, self.logins["adapter"][0], "effect.dispatch", self.dispatch_payload(effect, claim))
            activation = pool.submit(self.raw_api, self.logins["approver"][0], "contract.activate",
                                     {"contract_id": self.cid, "version": 2, "expected_active_version": 1})
            dispatched, activated = dispatch.result(), activation.result()
        self.assertTrue(activated["ok"], activated)
        current = self.ok("worker", "effect.get", {"effect_id": effect["effect_id"]})
        if dispatched["ok"]:
            self.assertLess(dispatched["event_id"], activated["event_id"])
            self.assertIsNotNone(current["dispatched_at"])
        else:
            self.assertEqual(dispatched["code"], "POLICY_INACTIVE")
            self.assertGreater(dispatched["event_id"], activated["event_id"])
            self.assertIsNone(current["dispatched_at"])

    def test_action_arguments_target_and_intent_identity_cannot_widen(self):
        candidate = self.passing_candidate()
        payload = {"candidate_id": candidate["candidate_id"], "action": "publish", "args": {},
                   "idempotency_key": self.cid + ":effect"}
        self.denied("worker", "effect.request", dict(payload, args={"path": "elsewhere"}), "ACTION_MISMATCH")
        self.denied("worker", "effect.request", dict(payload, target="elsewhere"), "INVALID_REQUEST")
        self.denied("worker", "effect.request", dict(payload, action="unapproved"), "ACTION_MISMATCH")
        effect = self.ok("worker", "effect.request", payload)
        self.assertEqual(self.ok("rotated", "effect.request", payload), effect)
        second = self.passing_candidate("second")
        self.denied("worker", "effect.request", dict(payload, candidate_id=second["candidate_id"]), "IDEMPOTENCY_CONFLICT")
        claim = self.claim_effect(effect)
        self.assertEqual(claim["target"], "reports/current.json")
        self.assertEqual(claim["args"], {})
        self.assertEqual(claim["artifact"]["content_hex"], self.content.hex())

    def test_real_controlled_consumer_requires_independent_matching_observation(self):
        candidate = self.passing_candidate()
        effect = self.request_effect(candidate)
        claim = self.claim_effect(effect)
        authority = self.ok("adapter", "effect.dispatch", self.dispatch_payload(effect, claim))
        self.assertTrue(authority["authorized"])
        destination = self.cluster.root / "consumer" / self.cid / claim["target"]
        destination.parent.mkdir(parents=True)
        content = bytes.fromhex(claim["artifact"]["content_hex"])
        self.assertEqual(hashlib.sha256(content).hexdigest(), claim["artifact"]["digest"])
        with destination.open("xb") as handle:
            handle.write(content)
        attempted = dict(self.dispatch_payload(effect, claim), outcome="attempted", receipt={"written": True})
        self.assertEqual(self.ok("adapter", "effect.report", attempted)["state"], "attempted")
        self.assertNotEqual(self.ok("worker", "effect.get", {"effect_id": effect["effect_id"]})["state"], "complete")
        observed = hashlib.sha256(destination.read_bytes()).hexdigest()
        self.assertEqual(destination.read_bytes(), self.content)
        response = self.ok("observer", "effect.observe", self.observe_payload(effect, digest=observed))
        self.assertEqual(response["state"], "complete")
        self.assertFalse(response["control_failure"])

    def test_cancellation_prevents_dispatch_and_unauthorized_reality_is_preserved(self):
        effect = self.request_effect(self.passing_candidate())
        claim = self.claim_effect(effect)
        self.assertEqual(self.ok("worker", "effect.cancel", {"effect_id": effect["effect_id"]})["state"], "cancelled")
        refused = self.denied("adapter", "effect.dispatch", self.dispatch_payload(effect, claim), "CANCELLED")
        observed = self.ok("observer", "effect.observe", self.observe_payload(effect))
        self.assertTrue(observed["control_failure"])
        current = self.ok("worker", "effect.get", {"effect_id": effect["effect_id"]})
        self.assertIsNone(current["dispatched_at"])
        self.assertIsNotNone(current["cancel_requested_at"])
        self.assertEqual({row["kind"] for row in current["reports"]}, {"cancellation", "observation"})
        self.assertGreater(observed["effect_id"], 0)
        self.assertGreater(refused["event_id"], 0)

    def test_cancellation_after_dispatch_does_not_claim_undo(self):
        effect = self.request_effect(self.passing_candidate())
        claim = self.claim_effect(effect)
        self.ok("adapter", "effect.dispatch", self.dispatch_payload(effect, claim))
        cancelled = self.ok("worker", "effect.cancel", {"effect_id": effect["effect_id"]})
        self.assertEqual(cancelled["state"], "dispatched")
        self.ok("observer", "effect.observe", self.observe_payload(effect))
        current = self.ok("worker", "effect.get", {"effect_id": effect["effect_id"]})
        self.assertEqual(current["state"], "complete")
        self.assertIsNotNone(current["dispatched_at"])
        self.assertIsNotNone(current["cancel_requested_at"])

    def test_uncertain_dispatch_is_never_automatically_replayed(self):
        effect = self.request_effect(self.passing_candidate())
        claim = self.claim_effect(effect, seconds=1)
        self.ok("adapter", "effect.dispatch", self.dispatch_payload(effect, claim))
        self.ok("adapter", "effect.report", dict(self.dispatch_payload(effect, claim), outcome="uncertain", receipt={"lost_response": True}))
        self.cluster.psql("SELECT pg_sleep(1.15)")
        self.denied("adapter", "effect.claim", {"effect_id": effect["effect_id"], "lease_seconds": 60}, "RECONCILIATION_REQUIRED")
        self.denied("adapter", "effect.dispatch", self.dispatch_payload(effect, claim))
        current = self.ok("worker", "effect.get", {"effect_id": effect["effect_id"]})
        self.assertEqual(current["state"], "uncertain")
        self.assertEqual(sum(row["kind"] == "dispatch" for row in current["reports"]), 1)

    def test_unreported_dispatch_requires_reconciliation_after_lease_expiry(self):
        effect = self.request_effect(self.passing_candidate())
        claim = self.claim_effect(effect, seconds=1)
        self.ok("adapter", "effect.dispatch", self.dispatch_payload(effect, claim))
        # The durable dispatch survives an absent adapter report. No completion
        # or safe-retry inference can be drawn from the missing response.
        self.cluster.psql("SELECT pg_sleep(1.15)")
        self.denied("adapter", "effect.claim", {"effect_id": effect["effect_id"], "lease_seconds": 60}, "RECONCILIATION_REQUIRED")
        current = self.ok("worker", "effect.get", {"effect_id": effect["effect_id"]})
        self.assertEqual(current["state"], "dispatched")
        self.assertEqual([row["kind"] for row in current["reports"]], ["dispatch"])
        observed = self.ok("observer", "effect.observe", self.observe_payload(effect, outcome="unknown"))
        self.assertEqual(observed["state"], "reconcile")
        self.denied("adapter", "effect.claim", {"effect_id": effect["effect_id"], "lease_seconds": 60}, "RECONCILIATION_REQUIRED")

    def test_expired_predispatch_claim_recovery_fences_old_adapter(self):
        effect = self.request_effect(self.passing_candidate())
        old = self.claim_effect(effect, seconds=1)
        self.cluster.psql("SELECT pg_sleep(1.15)")
        new = self.claim_effect(effect)
        self.assertGreater(new["generation"], old["generation"])
        self.denied("adapter", "effect.dispatch", self.dispatch_payload(effect, old), "LEASE_MISMATCH")
        self.ok("adapter", "effect.dispatch", self.dispatch_payload(effect, new))
        self.denied("adapter", "effect.dispatch", self.dispatch_payload(effect, new), "RECONCILIATION_REQUIRED")

    def test_adapter_lease_uses_wall_clock_inside_long_transaction(self):
        effect = self.request_effect(self.passing_candidate())
        claim = self.claim_effect(effect, seconds=1)
        sql = "BEGIN; SELECT pg_sleep(1.15); " + api_sql("effect.dispatch", self.dispatch_payload(effect, claim)) + " COMMIT;"
        result = self.cluster.psql(sql, user=self.logins["adapter"][0])
        response = json.loads(next(line for line in result.stdout.splitlines() if line.startswith("{")))
        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "LEASE_EXPIRED")
        self.assertIsNone(self.ok("worker", "effect.get", {"effect_id": effect["effect_id"]})["dispatched_at"])

    def test_observation_mismatch_cannot_be_erased_by_later_success(self):
        effect = self.request_effect(self.passing_candidate())
        claim = self.claim_effect(effect)
        self.ok("adapter", "effect.dispatch", self.dispatch_payload(effect, claim))
        mismatch = self.ok("observer", "effect.observe", self.observe_payload(effect, digest="0" * 64))
        self.assertTrue(mismatch["control_failure"])
        later = self.ok("observer", "effect.observe", self.observe_payload(effect))
        self.assertTrue(later["control_failure"])
        current = self.ok("worker", "effect.get", {"effect_id": effect["effect_id"]})
        self.assertEqual(current["state"], "control_failure")
        self.assertEqual(len([row for row in current["reports"] if row["kind"] == "observation"]), 2)

    def test_observer_must_differ_from_worker_and_adapter_stable_principals(self):
        doc = copy.deepcopy(self.document)
        doc["access"]["observers"] += ["independent-worker", "independent-adapter"]
        self.amend(doc)
        effect = self.request_effect(self.passing_candidate())
        claim = self.claim_effect(effect)
        self.ok("adapter", "effect.dispatch", self.dispatch_payload(effect, claim))
        self.denied("adapter", "effect.observe", self.observe_payload(effect), "FORBIDDEN")
        self.denied("self_observer", "effect.observe", self.observe_payload(effect), "SELF_JUDGING")
        self.denied("adapter_observer", "effect.observe", self.observe_payload(effect), "SELF_JUDGING")
        self.ok("observer", "effect.observe", self.observe_payload(effect))

    def test_malformed_parameters_unknown_fields_and_unknown_operations_refuse(self):
        candidate = self.submit()
        for payload in (None, [], "worker", {"candidate_id": True}, {"candidate_id": 1.5},
                        {"candidate_id": -1}, {"candidate_id": None},
                        {"candidate_id": candidate["candidate_id"], "accepted": True}):
            with self.subTest(payload=payload):
                self.denied("worker", "candidate.accept", payload, "INVALID_REQUEST")
        self.denied("worker", "invented.operation", {}, "UNKNOWN_OPERATION")
        for hex_content in ("0", "AB", "zz", None, True):
            with self.subTest(content=hex_content):
                self.denied("worker", "artifact.put", {"content_hex": hex_content, "media_type": "application/json"}, "INVALID_REQUEST")
        claim = self.claim(candidate)
        for field, invalid in (("token", "not-a-uuid"), ("generation", True), ("detail", []),
                               ("result", "success"), ("override", True)):
            payload = self.result_payload(candidate, claim)
            payload[field] = invalid
            with self.subTest(field=field):
                self.denied("verifier", "verification.record", payload, "INVALID_REQUEST")

    def test_malformed_contracts_do_not_become_active(self):
        changes = [lambda d: d.update(safe=True), lambda d: d.update(checks=[]),
                   lambda d: d["checks"].append(copy.deepcopy(d["checks"][0])),
                   lambda d: d["budgets"].update(research=True),
                   lambda d: d["budgets"].update(research=1.5),
                   lambda d: d["checks"][0].update(advisory=True),
                   lambda d: d["actions"][0].update(target="../outside")]
        for change in changes:
            doc = copy.deepcopy(self.document)
            change(doc)
            with self.subTest(document=doc):
                self.denied("worker", "contract.propose", {"contract_id": self.cid, "version": 2,
                                                            "document": doc})

    def test_audit_chain_and_denials_have_independent_raw_hash_verification(self):
        self.denied("worker", "invented.operation", {}, "UNKNOWN_OPERATION")
        payloads = [{"contract_id": self.cid, "budget": "research", "units": 1,
                     "idempotency_key": self.cid + ":audit-" + str(n)} for n in range(4)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda payload: self.raw_api(self.logins["worker"][0], "budget.consume", payload), payloads))
        self.assertTrue(all(row["ok"] for row in outcomes))
        exported = self.ok("auditor", "audit.export", {"after": 0, "limit": 1000})
        self.assertTrue(exported["chain_valid"])
        self.assertFalse(exported["administrator_rewrite_detection"])
        endpoint = exported["head"]["sequence"]
        raw = self.cluster.psql(
            "SELECT jsonb_build_object('seq',seq,'raw',event::text,'previous_hash',previous_hash,'hash',hash) "
            f"FROM hobnail.audit WHERE seq <= {endpoint} ORDER BY seq")
        rows = [json.loads(line) for line in raw.stdout.splitlines()]
        predecessor = "0" * 64
        for sequence, row in enumerate(rows, 1):
            self.assertEqual(row["seq"], sequence)
            self.assertEqual(row["previous_hash"], predecessor)
            computed = hashlib.sha256(bytes.fromhex(predecessor) + row["raw"].encode()).hexdigest()
            self.assertEqual(row["hash"], computed)
            predecessor = computed
        self.assertEqual(predecessor, exported["head"]["hash"])
        self.assertEqual(len(rows), endpoint)
        self.assertTrue(any(row["event"].get("code") == "UNKNOWN_OPERATION" for row in exported["events"]))

    def test_disposable_administrator_drift_is_reported_separately_from_chain(self):
        # Frozen case 9 explicitly requires disabled-enforcement detection. This
        # mutation is confined to this owned disposable cluster and is restored
        # even on assertion failure; it does not claim administrator prevention.
        baseline = self.ok("auditor", "audit.export", {"after": 0, "limit": 1})
        self.assertTrue(baseline["enforcement"]["immutable_triggers_valid"])
        self.assertTrue(baseline["enforcement"]["runtime_privileges_valid"])
        try:
            self.cluster.psql("ALTER TABLE hobnail.audit DISABLE TRIGGER audit_immutable")
            drifted = self.ok("auditor", "audit.export", {"after": 0, "limit": 1})
            self.assertTrue(drifted["chain_valid"])
            self.assertFalse(drifted["enforcement"]["immutable_triggers_valid"])
        finally:
            self.cluster.psql("ALTER TABLE hobnail.audit ENABLE TRIGGER audit_immutable")
        try:
            self.cluster.psql("GRANT SELECT ON hobnail.results TO accept_worker")
            self.denied("worker", "candidate.get", {"candidate_id": 1}, "FORBIDDEN")
            drifted = self.ok("auditor", "audit.export", {"after": 0, "limit": 1})
            self.assertTrue(drifted["chain_valid"])
            self.assertFalse(drifted["enforcement"]["runtime_privileges_valid"])
        finally:
            self.cluster.psql("REVOKE SELECT ON hobnail.results FROM accept_worker")
        restored = self.ok("auditor", "audit.export", {"after": 0, "limit": 1})
        self.assertTrue(restored["enforcement"]["immutable_triggers_valid"])
        self.assertTrue(restored["enforcement"]["runtime_privileges_valid"])


if __name__ == "__main__":
    unittest.main()
