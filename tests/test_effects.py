import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from hobnail.effects import EffectBoundaryError, FileObserver, FilePublisher


class ConsumerTests(unittest.TestCase):
    def test_actual_bytes_observed_independently_and_tamper_detected(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-consumer-") as directory:
            root = Path(directory).resolve()
            (root / "reports").mkdir(mode=0o700)
            content = b'{"approved":true}'
            digest = hashlib.sha256(content).hexdigest()
            publisher, observer = FilePublisher(root), FileObserver(root)
            self.assertEqual("absent", observer.observe("reports/current.json", digest)["outcome"])
            publisher.publish("reports/current.json", content, digest)
            self.assertEqual(content, (root / "reports/current.json").read_bytes())
            self.assertEqual("complete", observer.observe("reports/current.json", digest)["outcome"])
            (root / "reports/current.json").write_bytes(b"tampered")
            self.assertEqual("mismatch", observer.observe("reports/current.json", digest)["outcome"])

    def test_escape_alias_and_digest_mismatch_refuse(self):
        with tempfile.TemporaryDirectory(prefix="hobnail-consumer-") as directory:
            root = Path(directory).resolve()
            (root / "outside").mkdir()
            (root / "link").symlink_to(root / "outside", target_is_directory=True)
            publisher = FilePublisher(root)
            digest = hashlib.sha256(b"ok").hexdigest()
            for target in ("../escape", "/absolute", "a//b", "a/./b"):
                with self.assertRaises(EffectBoundaryError):
                    publisher.publish(target, b"ok", digest)
            with self.assertRaises(OSError):
                publisher.publish("link/escape", b"ok", digest)
            with self.assertRaises(EffectBoundaryError):
                publisher.publish("wrong", b"changed", digest)
            self.assertFalse((root / "outside/escape").exists())
            self.assertFalse((root / "wrong").exists())


if __name__ == "__main__":
    unittest.main()
