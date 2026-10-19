"""Exercise provenance, artifact staging, deadlines, and result completeness."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from qualification.artifacts import fingerprint, stage_artifacts
from qualification.configuration import check_packages, configuration, host_environment
from qualification.run import execute, fixture_tools, prepare, summarize, write_json
from qualification.sources import (
    QualificationError,
    git,
    pin_catalog,
    relative_path,
    resolve_sources,
)


class QualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "component"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "config", "user.name", "Qualification test")
        (self.repo / "tests").mkdir()
        self.test = self.repo / "tests/example.test.lua"
        self.test.write_text('test("example", function(t) t:assert(true) end)\n')
        write_json(
            self.repo / "suite.json",
            {
                "format": 1,
                "harness_only": True,
                "component": "example",
                "tests": ["tests/example.test.lua"],
                "files": {"tests/example.test.lua": "tests/example.test.lua"},
            },
        )
        self.commit()
        self.catalog = self.root / "suites.json"
        write_json(
            self.catalog,
            {
                "format": 1,
                "components": [
                    {"id": "example", "repository": "component", "manifest": "suite.json"}
                ],
            },
        )
        self.lock = self.root / "suites.lock.json"
        write_json(self.lock, pin_catalog(self.catalog))
        self.runner = self.root / "provium"
        self.runner.write_text(
            "#!/usr/bin/python3\nimport json, sys\n"
            "for path in sys.argv[1:]:\n"
            " if path.endswith('.test.lua'):\n"
            "  print(json.dumps(dict(path=path, timeout='in_time', passed=True, "
            "tests=[dict(name='example', status='passed')], chunk_error=None)))\n"
        )
        self.runner.chmod(0o755)
        self.spec = {
            "format": 1,
            "mode": "harness",
            "profiles": {},
            "artifacts": {"runner": {"path": str(self.runner), "sha256": fingerprint(self.runner)}},
            "runner": {"artifact": "runner"},
        }
        self.composition = self.root / "composition.json"
        self.output = self.root / "run"

    def commit(self) -> None:
        git(self.repo, "add", "suite.json", "tests")
        git(self.repo, "commit", "-qm", "test: record fixture")

    def prepare(self) -> dict:
        write_json(self.composition, self.spec)
        return prepare(self.lock, self.composition, self.output, [], {})

    def test_lock_ignores_changed_head_and_dirty_files(self) -> None:
        original = self.test.read_bytes()
        self.test.write_text("new committed input")
        self.commit()
        self.test.write_text("dirty input")
        files, tests, _ = resolve_sources(self.lock, [], {})
        self.assertEqual(files[tests[0]], original)

    def test_candidate_uses_committed_revision_and_rejects_dirty_tree(self) -> None:
        self.test.write_text("candidate")
        with self.assertRaisesRegex(QualificationError, "uncommitted"):
            resolve_sources(self.lock, [], {"example": self.repo})
        self.commit()
        files, tests, record = resolve_sources(self.lock, [], {"example": self.repo})
        self.assertEqual(files[tests[0]], b"candidate")
        self.assertTrue(record["sources"][0]["candidate"])

    def test_unknown_suite_is_an_error(self) -> None:
        with self.assertRaisesRegex(QualificationError, "Unknown components"):
            resolve_sources(self.lock, ["missing"], {})

    def test_tampered_manifest_is_rejected(self) -> None:
        data = json.loads(self.lock.read_text())
        data["components"][0]["manifest_sha256"] = "0" * 64
        write_json(self.lock, data)
        with self.assertRaisesRegex(QualificationError, "manifest mismatch"):
            resolve_sources(self.lock, [], {})

    def test_duplicate_exports_are_rejected(self) -> None:
        data = json.loads(self.lock.read_text())
        data["components"].append(data["components"][0])
        write_json(self.lock, data)
        with self.assertRaisesRegex(QualificationError, "Duplicate component"):
            resolve_sources(self.lock, [], {})

    def test_invalid_paths_are_rejected(self) -> None:
        for path in (".", "../outside", "/absolute", "tests/../file", "a//b", "a\\b"):
            with self.subTest(path=path), self.assertRaises(QualificationError):
                relative_path(path)

    def test_hash_mismatch_leaves_blocked_record(self) -> None:
        self.spec["artifacts"]["runner"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(QualificationError, "hash mismatch"):
            self.prepare()
        self.assertEqual(json.loads((self.output / "run.json").read_text())["status"], "blocked")
        self.assertFalse((self.output / "stdout.jsonl").exists())

    def test_special_files_and_escaping_links_are_rejected(self) -> None:
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(QualificationError):
            fingerprint(fifo)
        tree = self.root / "tree"
        tree.mkdir()
        (tree / "escape").symlink_to(self.runner)
        with self.assertRaisesRegex(QualificationError, "escapes"):
            fingerprint(tree)

    def test_tree_hash_is_independent_of_location(self) -> None:
        tree = self.root / "tree"
        tree.mkdir()
        (tree / "file").write_text("contents")
        (tree / "link").symlink_to("file")
        spec = {"artifacts": {"tree": {"path": str(tree), "sha256": fingerprint(tree)}}}
        paths, _ = stage_artifacts(spec, self.root, self.root / "artifacts")
        self.assertEqual(fingerprint(tree), fingerprint(paths["tree"]))
        (paths["tree"] / "file").chmod(0o755)
        self.assertNotEqual(fingerprint(tree), fingerprint(paths["tree"]))

    def test_builds_and_unrecorded_paths_are_rejected(self) -> None:
        for profile in ({"build": "touch BAD"}, {"kernel": "/unrecorded"}):
            with self.subTest(profile=profile), self.assertRaises(QualificationError):
                configuration({"profiles": {"test": profile}}, {}, self.root)

    def test_writable_disks_use_a_separate_copy(self) -> None:
        disk = self.root / "disk"
        disk.write_bytes(b"original")
        cfg = configuration(
            {
                "profiles": {
                    "test": {
                        "kernel": {"artifact": "disk"},
                        "inject_agent": False,
                        "disks": [{"path": {"artifact": "disk"}}],
                    }
                }
            },
            {"disk": disk},
            self.root,
        )
        working = self.root / "working-disks/test-0.img"
        self.assertIn(str(working), cfg)
        working.write_bytes(b"changed")
        self.assertEqual(disk.read_bytes(), b"original")

    def test_fixture_signing_resolves_prepared_bytes(self) -> None:
        unsigned, signed = self.root / "unsigned", self.root / "signed"
        unsigned.write_bytes(b"unsigned")
        signed.write_bytes(b"signed")
        fixture_tools(
            {"guest_tools": {"tool": {"unsigned": {"artifact": "u"}, "signed": {"artifact": "s"}}}},
            {"u": unsigned, "s": signed},
            self.root,
        )
        for _ in range(2):
            result = subprocess.run(
                ["sh", "tests/tools/sign.sh", str(unsigned), str(unsigned) + ".signed"],
                cwd=self.root,
                capture_output=True,
                check=True,
            )
            self.assertEqual(Path(result.stdout.decode().strip()).read_bytes(), b"signed")

    def test_passed_harness_does_not_qualify_os(self) -> None:
        record = self.prepare()
        self.assertEqual(execute(self.output, record, 5), 0)
        self.assertEqual(record["status"], "passed")
        self.assertFalse(record["qualification"])
        self.assertEqual(record["counts"]["passed"], 1)

    def test_missing_results_fail(self) -> None:
        with self.assertRaisesRegex(QualificationError, "each selected"):
            summarize("", ["tests/example.test.lua"], self.output)

    def test_skips_are_incomplete(self) -> None:
        self.runner.write_text(
            self.runner.read_text().replace("status='passed'", "status='skipped'")
        )
        self.spec["artifacts"]["runner"]["sha256"] = fingerprint(self.runner)
        record = self.prepare()
        self.assertEqual(execute(self.output, record, 5), 3)
        self.assertEqual(record["status"], "incomplete")
        self.assertFalse(record["qualification"])

    def test_failed_case_fails_even_when_runner_exits_zero(self) -> None:
        self.runner.write_text(
            self.runner.read_text().replace("status='passed'", "status='failed'")
        )
        self.spec["artifacts"]["runner"]["sha256"] = fingerprint(self.runner)
        record = self.prepare()
        self.assertEqual(execute(self.output, record, 5), 1)

    def test_timeout_reaps_process_and_records_failure(self) -> None:
        self.runner.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(30)\n")
        self.spec["artifacts"]["runner"]["sha256"] = fingerprint(self.runner)
        record = self.prepare()
        self.assertEqual(execute(self.output, record, 0.05), 1)
        self.assertEqual(record["status"], "failed")
        self.assertIn("timed out", record["error"])

    def test_system_mode_requires_declared_boot_inputs(self) -> None:
        self.spec["mode"] = "system"
        with self.assertRaisesRegex(QualificationError, "boot profiles"):
            self.prepare()

    def test_missing_commit_does_not_fall_back_to_head(self) -> None:
        data = json.loads(self.lock.read_text())
        data["components"][0]["revision"] = "0" * 40
        write_json(self.lock, data)
        with self.assertRaises(QualificationError):
            resolve_sources(self.lock, [], {})

    def test_manifest_cannot_export_runner_configuration(self) -> None:
        path = self.repo / "suite.json"
        manifest = json.loads(path.read_text())
        manifest["files"]["provium.toml"] = "tests/example.test.lua"
        write_json(path, manifest)
        self.commit()
        with self.assertRaisesRegex(QualificationError, "outside suite"):
            resolve_sources(self.lock, [], {"example": self.repo})

    def test_symlink_source_is_rejected(self) -> None:
        self.test.unlink()
        self.test.symlink_to("/etc/hostname")
        self.commit()
        with self.assertRaisesRegex(QualificationError, "regular Git files"):
            resolve_sources(self.lock, [], {"example": self.repo})

    def test_duplicate_file_reports_fail(self) -> None:
        line = json.dumps(
            {
                "path": "tests/example.test.lua",
                "passed": True,
                "timeout": "in_time",
                "tests": [{"status": "passed"}],
            }
        )
        with self.assertRaisesRegex(QualificationError, "exactly once"):
            summarize(line + "\n" + line, ["tests/example.test.lua"], self.output)

    def test_empty_file_fails(self) -> None:
        line = json.dumps(
            {"path": "tests/example.test.lua", "passed": True, "timeout": "in_time", "tests": []}
        )
        self.assertEqual(summarize(line, ["tests/example.test.lua"], self.output)["failed"], 1)

    def test_candidate_binary_and_service_inputs_are_recorded(self) -> None:
        env = host_environment(
            {
                "environment": {
                    "RESOLVD_TEST_BINARY": {"artifact": "candidate"},
                    "RESOLVD_TEST_SERVICE": {"artifact": "candidate"},
                }
            },
            {"candidate": self.runner},
            self.root,
        )
        self.assertEqual(env["RESOLVD_TEST_BINARY"], str(self.runner))
        with self.assertRaisesRegex(QualificationError, "explicit artifact"):
            host_environment({"environment": {"RESOLVD_TEST_SERVICE": "unrecorded"}}, {}, self.root)

    def test_package_identity_mismatch_is_rejected(self) -> None:
        manifest = self.root / "package.toml"
        manifest.write_text('name = "dev.example"\nversion = "1.0-1"\narch = "amd64"\n')
        spec = {
            "packages": [
                {
                    "name": "dev.example",
                    "version": "2.0-1",
                    "arch": "amd64",
                    "manifest": {"artifact": "package"},
                }
            ]
        }
        with self.assertRaisesRegex(QualificationError, "identity differs"):
            check_packages(spec, {"package": manifest})

    def test_changed_input_cannot_pass(self) -> None:
        record = self.prepare()
        (self.output / "artifacts/runner").write_text(self.runner.read_text() + "# change\n")
        self.assertEqual(execute(self.output, record, 5), 1)
        self.assertIn("changed during the run", record["error"])

    def test_input_output_collision_is_rejected(self) -> None:
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_text("existing")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(marker.read_text(), "existing")

    def test_invalid_timeout_is_rejected(self) -> None:
        for value in (0, -1, float("inf")):
            self.spec["file_timeout_seconds"] = value
            with self.subTest(value=value), self.assertRaises(QualificationError):
                self.prepare()
            shutil.rmtree(self.output)

    def test_new_test_cannot_be_silently_omitted_from_manifest(self) -> None:
        (self.repo / "tests/unlisted.test.lua").write_text('test("unlisted", function(t) end)')
        self.commit()
        with self.assertRaisesRegex(QualificationError, "inventory differs"):
            resolve_sources(self.lock, [], {"example": self.repo})

    def test_native_suite_cannot_run_on_local_backend(self) -> None:
        path = self.repo / "suite.json"
        manifest = json.loads(path.read_text())
        del manifest["harness_only"]
        write_json(path, manifest)
        self.commit()
        write_json(self.lock, pin_catalog(self.catalog))
        with self.assertRaisesRegex(QualificationError, "harness-only"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
