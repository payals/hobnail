"""Actual installed optional dependency, stdio, SQL and native role consequences.

Missing reviewed prerequisites are failures, never skipped qualification.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.mcp_demo import run_demo


class MCPRuntimeTests(unittest.TestCase):
    def check_protocol(self, protocol):
        result = run_demo(protocol_version=protocol, source_server=True)
        self.assertEqual(result["status"], "passed", {"failure": result.get("failure"), "receipt": result["receipt"]})
        self.assertTrue(result["runtime_stopped"])
        self.assertTrue(result["checks"]["all_runtime_credentials_revoked"])
        self.assertTrue(result["checks"]["generated_passwords_absent_from_receipt_and_logs"])
        self.assertEqual(result["checks"]["mcp_process"]["protocol"], protocol)
        self.assertEqual(result["checks"]["mcp_process"]["returncode"], 0)
        self.assertEqual([row["name"] for row in result["scenarios"]], ["happy", "bad", "stale", "cancel"])
        self.assertTrue(all(row["stage"] == "completed" for row in result["scenarios"]))
        self.assertFalse(result["qualified"])

    def test_legacy_stdio_real_roles_bytes_replays_refusals_and_cleanup(self):
        self.check_protocol("2025-11-25")

    def test_modern_stdio_real_roles_bytes_replays_refusals_and_cleanup(self):
        self.check_protocol("2026-07-28")


if __name__ == "__main__":
    unittest.main()
