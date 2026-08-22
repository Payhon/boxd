import importlib.util
import os
import stat
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "scripts" / "phase4-kvm-probe.py"
SPEC = importlib.util.spec_from_file_location("phase4_kvm_probe", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class KvmProbeTests(unittest.TestCase):
    def setUp(self):
        self.fd = 42
        self.opened = []

    def fake_stat(self, _device):
        return os.stat_result((stat.S_IFCHR | 0o660, 0, 0, 1, 0, 0, 0, 0, 0, 0))

    def fake_open(self, device, flags):
        self.opened.append((device, flags))
        return self.fd

    def fake_close(self, fd):
        self.assertEqual(fd, self.fd)

    def run_probe(self, **kwargs):
        options = {
            "system": "Linux", "machine": "x86_64", "stat_fn": self.fake_stat,
            "open_fn": self.fake_open, "close_fn": self.fake_close,
        }
        options.update(kwargs)
        return MODULE.probe(**options)

    def test_schema_and_fake_backend_pass(self):
        result = self.run_probe(ioctl_fn=lambda fd, request, arg: 12)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["kvm_api_version"], 12)
        self.assertEqual(result["checks"]["character_device"], "pass")
        self.assertTrue(self.opened[0][1] & os.O_RDWR)

    def test_missing_device_is_blocked(self):
        result = self.run_probe(stat_fn=lambda _device: (_ for _ in ()).throw(FileNotFoundError("missing")))
        self.assertEqual(result["status"], "blocked")
        self.assertIn("cannot stat", result["blocked_reason"])

    def test_wrong_api_version_is_blocked(self):
        result = self.run_probe(ioctl_fn=lambda fd, request, arg: 11)
        self.assertEqual(result["status"], "blocked")
        self.assertIn("expected 12", result["blocked_reason"])


if __name__ == "__main__":
    unittest.main()
