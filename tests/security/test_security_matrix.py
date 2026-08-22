import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALID = ROOT / "tests/security/cases.json"
VALIDATOR = ROOT / "scripts/phase4-security-matrix.py"


def run(cases: Path, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--cases", str(cases)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != expected:
        raise AssertionError(f"expected {expected}, got {result.returncode}: {result.stderr}")
    return result


class SecurityMatrixTests(unittest.TestCase):
    def test_valid_matrix_is_accepted_without_case_payload_output(self) -> None:
        result = run(VALID)
        self.assertIn('"status": "pass"', result.stdout)
        self.assertNotIn("secret_fixture", result.stdout)

    def test_unknown_category_fails_closed(self) -> None:
        value = json.loads(VALID.read_text(encoding="utf-8"))
        value["cases"][0]["category"] = "unknown"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = run(path, expected=1)
            self.assertIn("unsupported category", result.stderr)

    def test_missing_negative_case_fails_closed(self) -> None:
        value = json.loads(VALID.read_text(encoding="utf-8"))
        value["cases"] = [case for case in value["cases"] if case["positive"]]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = run(path, expected=1)
            self.assertIn("negative", result.stderr)

    def test_secret_like_value_is_rejected(self) -> None:
        value = json.loads(VALID.read_text(encoding="utf-8"))
        value["cases"][0]["fixture"] = "ghp_012345678901234567890123456789012345"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = run(path, expected=1)
            self.assertIn("secret-like", result.stderr)


if __name__ == "__main__":
    unittest.main()
