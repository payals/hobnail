#!/usr/bin/env python3
"""Seed transport and evidence failures around actual owned Docker operations.

These are qualification controls, not naturally occurring incidents. Every
injected transport error follows a real operation; policy and cleanup remain
the production supervisor's. No runtime artifact approval is supplied here.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import os
import stat

from scripts.docker_runtime import DockerError, DockerRuntime
from hobnail.credentials import CredentialProfile, CredentialRequest, PostgresCredentialProvider


class InjectedDockerFault(DockerError):
    """A deliberately lost response from an operation that actually ran."""


class _FaultRuntime(DockerRuntime):
    lose_create_reply = False
    lose_ready_reply = False

    def _cli(self, arguments, **options):
        response = super()._cli(arguments, **options)
        if self.lose_create_reply and arguments[:2] == ["container", "create"]:
            self.lose_create_reply = False
            self._event("qualification-created-reply-lost", container_id=response)
            raise InjectedDockerFault("created_container_reply_lost")
        return response

    @contextmanager
    def hold_endpoint(self, endpoint):
        with super().hold_endpoint(endpoint) as held:
            # The production context yields only after exact readiness,
            # authentication, identity and running-policy validation.
            if self.lose_ready_reply:
                self.lose_ready_reply = False
                self._event("qualification-ready-reply-lost", container_id=held["container_id"],
                            running=True, pid=held["host_pid"], ready_response=held["ready_response"])
                raise InjectedDockerFault("held_peer_ready_reply_lost")
            yield held


class _LostIssuanceProvider(PostgresCredentialProvider):
    lose_issuance_reply = False

    def _json(self, sql, **options):
        result = super()._json(sql, **options)
        if self.lose_issuance_reply and "CREATE TEMP TABLE hobnail_credential_material" in sql:
            # SQL committed but issue() has not constructed/cached its lease or
            # returned credential material. Recovery must read real role
            # metadata, never manufacture another credential or its password.
            self.lose_issuance_reply = False
            raise InjectedDockerFault("credential_issuance_reply_lost")
        return result


def _capture(operation):
    try:
        operation()
    except Exception as error:
        return {"error": type(error).__name__}
    return {"returned": True}


def _unrelated(runtime, identities=None):
    if identities is None:
        identities = runtime._cli(["container", "ls", "--all", "--no-trunc", "--quiet"]).splitlines()
    template = ('{"id":{{json .Id}},"running":{{json .State.Running}},'
                '"status":{{json .State.Status}},"started_at":{{json .State.StartedAt}},'
                '"restart_count":{{json .RestartCount}},'
                '"health":{{with index .State "Health"}}{{json .Status}}{{else}}null{{end}}}')
    return {identity: runtime._json(["container", "inspect", "--format", template, identity])
            for identity in sorted(identities)}


def _removed(runtime, previous):
    records = [record for name, record in runtime.containers.items() if name not in previous]
    result = []
    for item in records:
        if not item["id"]:
            raise DockerError("fault container identity remains unconfirmed")
        present = runtime._cli(["container", "ls", "--all", "--no-trunc", "--quiet",
                                "--filter", "id=" + item["id"]]).splitlines()
        result.append({"id": item["id"], "state": item["state"], "present": bool(present),
                       "cleanup_observed_state": item.get("cleanup_observed_state"),
                       "exit_code": item.get("exit_code")})
    return result


def qualify_lifecycle_faults(record, configuration):
    """Keep expected failure receipts, then independently reconcile resources."""
    runtime = _FaultRuntime(**configuration)
    original_mode = stat.S_IMODE(runtime.receipt_dir.stat().st_mode)
    primary = None
    try:
        before = record.step("faults-unrelated-before", lambda: _unrelated(runtime))
        record.step("faults-runtime-start", runtime.start,
                    summary=lambda _: {"root": str(runtime.root), "run_id": runtime.run_id,
                                       "daemon": runtime.ownership["daemon"]})
        record.secrets.append(runtime.admin.connection.password)
        provider = _LostIssuanceProvider(runtime.admin, provider_id="fault-" + runtime.run_id,
            profiles={"fault-worker": CredentialProfile("fault-worker", frozenset({"fault-worker"}),
                                                          "worker", 120, 180)})
        runtime.providers.append(provider)
        def issue():
            lease = provider.issue(CredentialRequest(1, "fault-worker", "fault-worker", "worker", 120))
            record.secrets.append(lease.password.reveal())
            runtime._sensitive.add(lease.password.reveal())
            return lease
        lease = record.step("faults-issued-credential", issue,
            summary=lambda value: {"login": value.login, "lease_ref": value.lease_ref})
        endpoint = runtime.endpoint("worker", replace(runtime.admin.connection,
                                     user=lease.login, password=lease.password.reveal()))

        provider.lose_issuance_reply = True
        request = CredentialRequest(2, "fault-worker", "fault-worker", "worker", 120)
        lost = record.step("faults-issuance-lost-reply", lambda: _capture(lambda: provider.issue(request)))
        record.check("faults-issuance-error-preserved", lost == {"error": "InjectedDockerFault"}
                     and provider.lose_issuance_reply is False and 2 not in provider._issued)
        recovered = record.step("faults-issuance-inventory", provider.inventory,
            summary=lambda values: [{"request_id": value.request_id, "login": value.login,
                                      "lease_ref": value.lease_ref, "material_available": value.password is not None}
                                     for value in values])
        unknown = [value for value in recovered if value.request_id == 2]
        record.check("faults-issuance-custody-recovered", len(unknown) == 1 and unknown[0].password is None)
        active = record.step("faults-issuance-role-active", lambda: provider.observe(unknown[0].lease_ref),
            summary=lambda value: {"result": value.result, "login_enabled": value.login_enabled})
        record.check("faults-issuance-role-active", active.result == "active" and active.login_enabled is True)
        retry = record.step("faults-issuance-blind-retry-refused", lambda: _capture(lambda: provider.issue(request)))
        record.check("faults-issuance-no-new-credential", retry == {"error": "CredentialError"}
                     and len(provider.inventory()) == 2)

        evidence_root = runtime.root / "issuance-receipt-fault"
        evidence_root.mkdir(mode=0o700)
        failed_receipt = type(record)(evidence_root)
        captured = []
        write_denials = []
        def issue_then_lose_receipt():
            value = provider.issue(CredentialRequest(3, "fault-worker", "fault-worker", "worker", 120))
            captured.append(value)
            record.secrets.append(value.password.reveal())
            failed_receipt.secrets.append(value.password.reveal())
            runtime._sensitive.add(value.password.reveal())
            evidence_root.chmod(0o500)
            def write_probe():
                descriptor = os.open(evidence_root / ".postissuance-write-check",
                                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(descriptor)
            write_denials.append(_capture(write_probe))
            return value
        try:
            failed = record.step("faults-postissuance-receipt-lost", lambda: _capture(lambda:
                failed_receipt.step("issuance", issue_then_lose_receipt,
                    summary=lambda value: {"login": value.login, "lease_ref": value.lease_ref})))
        finally:
            evidence_root.chmod(0o700)
        # Recorder independently checks the owned directory's mode before it
        # attempts a write. Preserve that actual ValueError, together with the
        # separate real filesystem PermissionError; never bypass its guard.
        record.check("faults-postissuance-custody-preserved", failed == {"error": "ValueError"}
                     and write_denials == [{"error": "PermissionError"}]
                     and len(captured) == 1 and 3 in provider._issued)
        failed_receipt.receipt.update(status="failed", failure={"type": failed["error"],
            "reason": "seeded_postissuance_receipt_persistence_failure"})
        failed_receipt.persist()
        record.step("faults-postissuance-retained-failure", lambda: {"receipt": str(failed_receipt.path),
            "status": failed_receipt.receipt["status"], "login": captured[0].login,
            "filesystem_write": write_denials[0], "persistence": failed})
        active = record.step("faults-postissuance-role-active", lambda: provider.observe(captured[0].lease_ref),
            summary=lambda value: {"result": value.result, "login_enabled": value.login_enabled})
        record.check("faults-postissuance-role-active", active.result == "active" and active.login_enabled is True)

        previous = set(runtime.containers)
        runtime.lose_create_reply = True
        failed = record.step("faults-launch-lost-reply", lambda: _capture(
            lambda: runtime.probe(endpoint, {"command": "self"})))
        record.check("faults-launch-error-preserved", failed == {"error": "InjectedDockerFault"}
                     and runtime.lose_create_reply is False)
        removed = record.step("faults-launch-removed", lambda: _removed(runtime, previous))
        record.check("faults-launch-exact-removal", len(removed) == 1
                     and removed[0]["state"] == "removed" and removed[0]["present"] is False)

        previous = set(runtime.containers)
        runtime.lose_ready_reply = True
        def readiness():
            with runtime.hold_endpoint(endpoint):
                raise AssertionError("readiness response was not lost")
        failed = record.step("faults-readiness-lost-reply", lambda: _capture(readiness))
        record.check("faults-readiness-error-preserved", failed == {"error": "InjectedDockerFault"}
                     and runtime.lose_ready_reply is False)
        removed = record.step("faults-readiness-removed", lambda: _removed(runtime, previous))
        ready = [event for event in runtime.events if event["operation"] == "qualification-ready-reply-lost"]
        record.step("faults-readiness-positive-observation", lambda: ready)
        record.check("faults-readiness-exact-removal", len(removed) == 1 and len(ready) == 1
                     and removed[0]["id"] == ready[0]["container_id"]
                     and ready[0]["running"] is True and ready[0]["pid"] > 0
                     and ready[0]["ready_response"] == {"ready": True, "login": lease.login}
                     and removed[0]["state"] == "removed" and removed[0]["present"] is False)

        positive = record.step("faults-credential-positive-before-cleanup", lambda: provider.observe(lease.lease_ref),
                               summary=lambda value: {"result": value.result, "login_enabled": value.login_enabled})
        record.check("faults-credential-positive-before-cleanup", positive.result == "active"
                     and positive.login_enabled is True)
        runtime.receipt_dir.chmod(0o500)
        try:
            def denied_write():
                descriptor = os.open(runtime.receipt_dir / ".injected-unwritable-check",
                                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(descriptor)
                raise AssertionError("owned directory unexpectedly permitted a write")
            write = record.step("faults-receipt-write-denial", lambda: _capture(denied_write))
            record.check("faults-receipt-denial-is-real", write == {"error": "PermissionError"})
            failed = record.step("faults-receipt-cleanup-error", lambda: _capture(runtime.close))
        finally:
            # Restore only the directory created by this control. The failed
            # cleanup flags are retained and are never converted into success.
            runtime.receipt_dir.chmod(original_mode)
            runtime._persist()
        record.check("faults-receipt-error-preserved", failed == {"error": "DockerError"}
                     and runtime.ownership["status"] == "cleanup-unconfirmed"
                     and "cleanup-receipt-persistence-failed" in runtime.ownership["cleanup_failures"])
        record.step("faults-retained-cleanup-failure", lambda: {
            "ownership_path": str(runtime.receipt_dir / "ownership.json"),
            "cleanup_failures": runtime.ownership["cleanup_failures"],
            "administrator_retirement": runtime.ownership.get("administrator_retirement"),
            "credential_retirement": runtime.ownership.get("credential_retirement"),
            "source": runtime.ownership.get("source"), "images": runtime.images,
            "fault_events": [event for event in runtime.events if event["operation"].startswith("qualification-")]})
        retired = runtime.ownership.get("credential_retirement", [])
        record.check("faults-credential-actually-retired", len(retired) == 3
                     and {value["login"] for value in retired} == {lease.login, unknown[0].login, captured[0].login}
                     and all(value["result"] == "confirmed" and value["login_enabled"] is False
                             and value["active_sessions"] == 0 for value in retired))
        record.check("faults-administrator-actually-retired", runtime.ownership.get("administrator_retirement") ==
                     {"result": "confirmed", "login_enabled": False, "other_client_sessions": 0})
        removed = record.step("faults-all-resources-observed-absent", lambda: _removed(runtime, set()))
        record.check("faults-all-resources-retired", runtime.closed and not runtime.active and bool(removed)
                     and all(item["state"] == "removed" and item["present"] is False for item in removed))
        after = record.step("faults-unrelated-after", lambda: _unrelated(runtime, before))
        record.check("faults-unrelated-preserved", before == after)
        runtime.assert_snapshot()
    except BaseException as error:
        primary = error
        raise
    finally:
        runtime.receipt_dir.chmod(original_mode)
        if not runtime.closed:
            try:
                runtime.close()
            except Exception as error:
                if primary is None:
                    raise
                record.receipt["cleanup_failures"].append({"stage": "fault_runtime_close",
                                                         "type": type(error).__name__})
                primary.add_note("Fault-control cleanup also failed; the original failure is preserved.")
