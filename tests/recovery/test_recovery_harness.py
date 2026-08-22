import importlib.util, json, pathlib, unittest
ROOT = pathlib.Path(__file__).parents[2]
def load():
    spec = importlib.util.spec_from_file_location("recovery", ROOT / "scripts/phase4-recovery-harness.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class RecoveryHarnessTests(unittest.TestCase):
    def test_matrix_is_complete_but_blocked(self):
        m = load(); d = json.loads((ROOT / "tests/recovery/fixture.json").read_text()); m.validate(d); self.assertEqual(m.evidence(d)["summary"]["status"], "blocked")
