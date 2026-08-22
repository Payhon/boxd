import importlib.util, json, pathlib, unittest
ROOT = pathlib.Path(__file__).parents[2]
def load():
    spec = importlib.util.spec_from_file_location("load", ROOT / "scripts/phase4-load-harness.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class LoadHarnessTests(unittest.TestCase):
    def test_matrix_is_complete_but_blocked(self):
        m = load(); d = json.loads((ROOT / "tests/load/fixture.json").read_text()); m.validate_fixture(d); self.assertEqual(m.evidence(d)["summary"]["status"], "blocked")
    def test_secret_rejected(self):
        m = load(); d = {"schema":m.SCHEMA,"mode":"fixture","runs":[]}; self.assertRaises(m.HarnessError, m.validate_fixture, d)
