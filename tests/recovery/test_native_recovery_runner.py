import importlib.util
import json
import os
import pathlib
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).parents[2]


def load_runner():
    spec = importlib.util.spec_from_file_location("native_recovery", ROOT / "scripts/phase4-native-recovery.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class NativeRecoveryRunnerTests(unittest.TestCase):
    def test_work_directory_is_limited_to_runner_temp_and_new(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}, clear=False):
                work = runner.prepare_work_dir(runner_temp / "owned")
                self.assertEqual(work.parent, runner_temp.resolve())
                self.assertTrue((work / "tmp").is_dir())
                with self.assertRaises(runner.RunnerError):
                    runner.prepare_work_dir(root / "outside")

    def test_data_tree_rejects_symlink_and_hardlink_aliases(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            work = root / "work"
            data = work / "data"
            data.mkdir(parents=True)
            source = data / "one"
            source.write_bytes(b"one")
            self.assertEqual(runner.verify_data_tree(data, work)["regular_files"], 1)
            alias = data / "alias"
            os.link(source, alias)
            with self.assertRaises(runner.RunnerError):
                runner.verify_data_tree(data, work)
            alias.unlink()
            alias.symlink_to(source)
            with self.assertRaises(runner.RunnerError):
                runner.verify_data_tree(data, work)

    def test_sqlite_integrity_is_real_and_not_a_fixture_status(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temp:
            database = pathlib.Path(temp) / "boxd.sqlite3"
            connection = sqlite3.connect(database)
            connection.execute("create table boxes (id integer primary key)")
            connection.execute("insert into boxes values (1)")
            connection.commit()
            connection.close()
            result = runner.verify_sqlite(database)
            self.assertEqual(result["integrity_check"], "ok")
            self.assertGreaterEqual(result["page_count"], 1)

    def test_init_key_is_parsed_without_writing_plaintext_to_logs(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            binary = root / "boxd-init-test"
            binary.write_text("#!/bin/sh\nprintf 'compat_api_key=boxd_compat_test_secret\\n'\n", encoding="utf-8")
            binary.chmod(0o700)
            key = runner.initialize_database(root, binary, root / "bootstrap" / "boxd.toml", dict(os.environ))
            self.assertEqual(key, "boxd_compat_test_secret")
            log = (root / "logs/database-init.log").read_text(encoding="utf-8")
            self.assertNotIn(key, log)
            self.assertIn("compat_api_key=[REDACTED]", log)

    def test_init_rejects_multiple_compatibility_key_lines(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            binary = root / "boxd-init-test"
            binary.write_text(
                "#!/bin/sh\nprintf 'compat_api_key=boxd_compat_first_secret\\ncompat_api_key=boxd_compat_second_secret\\n'\n",
                encoding="utf-8",
            )
            binary.chmod(0o700)
            with self.assertRaises(runner.RunnerError):
                runner.initialize_database(root, binary, root / "bootstrap" / "boxd.toml", dict(os.environ))
            log = (root / "logs/database-init.log").read_text(encoding="utf-8")
            self.assertNotIn("boxd_compat_first_secret", log)
            self.assertNotIn("boxd_compat_second_secret", log)

    def test_bound_binary_copy_keeps_exec_mode_and_hash(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            source = root / "boxd"
            target = root / "artifacts/boxd"
            source.write_bytes(b"bound-boxd")
            source.chmod(0o700)
            digest = runner.copy_input(source, target, "boxd", mode=0o700)
            self.assertTrue(stat.S_IXUSR & target.stat().st_mode)
            self.assertEqual(digest, runner.sha256(target))

    def test_config_rewrite_is_closed_to_runner_owned_paths(self):
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            target = root / "generated.toml"
            data = root / "data"
            runner.replace_config(ROOT / "config/boxd.example.toml", target, data, 17431)
            text = target.read_text(encoding="utf-8")
            self.assertIn(json.dumps(f"127.0.0.1:17431"), text)
            self.assertIn(json.dumps(f"sqlite://{data / 'boxd.sqlite3'}?mode=rwc"), text)
            self.assertIn(json.dumps(str(data / "boxes")), text)
            self.assertNotIn(str(ROOT), text)


if __name__ == "__main__":
    unittest.main()
