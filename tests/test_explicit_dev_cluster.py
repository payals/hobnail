"""Owned explicit layout needed by the frozen local OpenBao reference."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.dev_cluster import ClusterError, DevCluster, MARKER


class ExplicitClusterTests(unittest.TestCase):
    def test_explicit_root_socket_roundtrip_restart_and_retained_data(self):
        parent = Path(tempfile.mkdtemp(prefix="hbn-reference-", dir="/tmp")).resolve()
        cluster = DevCluster(root=parent / "postgres", socket_name="socket", database="hobnail_reference")
        try:
            cluster.start()
            self.assertEqual(cluster.socket_dir, parent / "postgres/socket")
            cluster.psql("CREATE TABLE kept(v int); INSERT INTO kept VALUES(17)")
            reopened = DevCluster.from_path(cluster.root)
            self.assertEqual(reopened.status()["pid"], cluster.status()["pid"])
            self.assertEqual(reopened.socket_dir, cluster.socket_dir)
            reopened.stop()
            reopened.start()
            self.assertEqual(reopened.psql("SELECT v FROM kept").stdout.strip(), "17")
            reopened.stop()
        finally:
            # Refresh a marker legitimately updated by the attached handle.
            DevCluster.from_path(cluster.root).stop()

    def test_explicit_root_never_adopts_existing_directory_or_alias(self):
        parent = Path(tempfile.mkdtemp(prefix="hbn-reference-", dir="/tmp")).resolve()
        existing = parent / "existing"
        existing.mkdir()
        sentinel = existing / "sentinel"
        sentinel.write_text("preserve")
        with self.assertRaises(FileExistsError):
            DevCluster(root=existing)
        alias = parent / "alias"
        alias.symlink_to(existing, target_is_directory=True)
        with self.assertRaises(ClusterError):
            DevCluster(root=alias / "new")
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertFalse((existing / MARKER).exists())
        self.assertFalse((existing / "new").exists())

    def test_changed_socket_marker_refuses_before_runtime_action(self):
        cluster = DevCluster(socket_name="socket")
        path = cluster.root / MARKER
        original = path.read_text()
        value = json.loads(original)
        value["socket_name"] = "sock"
        path.write_text(json.dumps(value))
        try:
            with self.assertRaisesRegex(ClusterError, "ownership marker changed"):
                cluster.start()
            self.assertFalse(cluster.data_dir.exists())
        finally:
            path.write_text(original)
        self.assertFalse(cluster.is_running())

    def test_explicit_root_rejects_shared_writable_parent(self):
        parent = Path(tempfile.mkdtemp(prefix="hbn-reference-", dir="/tmp")).resolve()
        parent.chmod(0o777)
        try:
            with self.assertRaisesRegex(ClusterError, "not writable by others"):
                DevCluster(root=parent / "postgres")
            self.assertFalse((parent / "postgres").exists())
        finally:
            parent.chmod(0o700)

    def test_legacy_marker_without_socket_name_roundtrip(self):
        cluster = DevCluster()
        path = cluster.root / MARKER
        value = json.loads(path.read_text())
        del value["socket_name"]
        path.write_text(json.dumps(value))
        reopened = DevCluster.from_path(cluster.root)
        try:
            reopened.start()
            self.assertEqual(reopened.socket_dir, cluster.root / "sock")
            self.assertEqual(reopened.psql("SELECT 17").stdout.strip(), "17")
        finally:
            reopened.stop()


if __name__ == "__main__":
    unittest.main()
