"""Audit checkpoints test raw bytes, independent anchors and moving export heads."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hobnail.audit import AuditError, Checkpoint, GENESIS, export_verified, verify_page


def row(sequence, previous, canonical):
    return {"seq": sequence, "previous_hash": previous,
            "hash": hashlib.sha256(bytes.fromhex(previous) + canonical.encode()).hexdigest(),
            "event": json.loads(canonical), "event_canonical": canonical}


class AuditTests(unittest.TestCase):
    def setUp(self):
        # Deliberate ordering/spacing/numeric representation differs from a
        # Python re-serialization. The verifier must hash these exact bytes.
        self.first = row(1, GENESIS.hash, '{"n": 1.00, "sequence": 1, "detail": {"ok": true}}')
        self.second = row(2, self.first["hash"], '{"sequence": 2, "operation": "observe", "value": "café"}')
        self.head = Checkpoint(2, self.second["hash"])
        self.page = {"events": [self.first, self.second], "head": self.head.as_dict(), "chain_valid": True}

    def test_exact_canonical_bytes_verify_without_reserialization(self):
        result = verify_page(self.page)
        self.assertEqual(result.checkpoint, self.head)
        self.assertTrue(result.complete)
        self.assertEqual(result.verified_events, 2)

    def test_server_boolean_does_not_replace_local_verification(self):
        page = copy.deepcopy(self.page)
        page["chain_valid"] = False
        self.assertTrue(verify_page(page).complete)
        page["chain_valid"] = True
        page["events"][0]["event_canonical"] = page["events"][0]["event_canonical"].replace('1.00', '9.00')
        with self.assertRaises(AuditError):
            verify_page(page)

    def test_missing_raw_text_is_not_reconstructed_from_json(self):
        page = copy.deepcopy(self.page)
        del page["events"][0]["event_canonical"]
        with self.assertRaisesRegex(AuditError, "event_canonical"):
            verify_page(page)

    def test_display_field_tamper_and_boolean_number_alias_refuse(self):
        for value in (False, 1):
            with self.subTest(value=value):
                page = copy.deepcopy(self.page)
                page["events"][0]["event"]["detail"]["ok"] = value
                with self.assertRaisesRegex(AuditError, "display event"):
                    verify_page(page)

    def test_gaps_reordering_and_missing_tail_refuse(self):
        for events in ([self.second], [self.second, self.first], []):
            with self.subTest(events=events):
                with self.assertRaises(AuditError):
                    verify_page({**self.page, "events": events})
        partial = verify_page({**self.page, "events": [self.first]})
        self.assertFalse(partial.complete)
        with self.assertRaises(AuditError):
            verify_page({**self.page, "events": []}, checkpoint=partial.checkpoint, target=partial.target)

    def test_authentic_checkpoint_detects_rewrite_and_truncation(self):
        anchor = Checkpoint(1, self.first["hash"])
        rewritten = copy.deepcopy(self.page)
        rewritten["head"] = {"sequence": 1, "hash": "a" * 64}
        with self.assertRaises(AuditError):
            verify_page(rewritten, checkpoint=anchor)
        with self.assertRaises(AuditError):
            verify_page({"head": GENESIS.as_dict(), "events": []}, checkpoint=anchor)
        tail = verify_page({**self.page, "events": [self.second]}, checkpoint=anchor)
        self.assertEqual(tail.checkpoint, self.head)

    def test_duplicate_keys_cannot_hide_hashed_display_difference(self):
        first = row(1, GENESIS.hash, '{"sequence": 1, "ok": false, "ok": true}')
        with self.assertRaises(AuditError):
            verify_page({"head": {"sequence": 1, "hash": first["hash"]}, "events": [first]})

    def test_pagination_anchors_first_head_despite_export_events(self):
        third = row(3, self.second["hash"], '{"sequence": 3, "operation": "audit.export"}')
        calls = []
        pages = [{"head": self.head.as_dict(), "events": [self.first]},
                 {"head": {"sequence": 3, "hash": third["hash"]}, "events": [self.second]}]
        class Client:
            def require(self, operation, payload):
                calls.append((operation, payload))
                return {"data": pages.pop(0)}
        report = export_verified(Client(), page_size=1)
        self.assertEqual(report.checkpoint, self.head)
        self.assertEqual(report.pages, 2)
        self.assertFalse(report.externally_anchored)
        self.assertEqual([payload["after"] for _, payload in calls], [0, 1])

    def test_page_budget_does_not_claim_partial_completion(self):
        class Client:
            def require(inner, operation, payload):
                return {"data": {**self.page, "events": [self.first]}}
        with self.assertRaisesRegex(AuditError, "page budget"):
            export_verified(Client(), page_size=1, max_pages=1)

    def test_checkpoint_types_and_genesis_are_strict(self):
        for sequence, digest in ((True, "0" * 64), (-1, "0" * 64), (0, "a" * 64), (1, "A" * 64)):
            with self.subTest(sequence=sequence, digest=digest):
                with self.assertRaises(AuditError):
                    Checkpoint(sequence, digest)
