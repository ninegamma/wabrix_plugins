"""CLI regression tests for syncing WIT and verifying Cargo's SDK dependency."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from sync_wit import compatible_version


SCRIPT = Path(__file__).with_name("sync_wit.py")
WIT = b"package wabrix:plugins@0.2.0;\n\nworld engine-plugin {}\n"


class SyncWitTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="wabrix-wit-sync-tests-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        # Cargo's offline switch also blocks uncached file:// Git remotes.
        self.environment = dict(
            os.environ, CARGO_HOME=str(root / "cargo-cache"), CARGO_NET_OFFLINE="false"
        )
        self.sdk = root / "sdk"
        self.sdk.mkdir()
        self.plugin = root / "plugins"
        (self.plugin / "scripts").mkdir(parents=True)
        shutil.copyfile(SCRIPT, self.plugin / "scripts/sync_wit.py")

    def git(self, *arguments):
        return subprocess.check_output(
            [
                "git", "-c", "user.name=WIT sync tests",
                "-c", "user.email=wit-sync-test@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                *arguments,
            ],
            cwd=self.sdk,
            stderr=subprocess.PIPE,
        )

    def commit_sdk(self, manifest):
        (self.sdk / "Cargo.toml").write_text(manifest)
        (self.sdk / "src").mkdir()
        (self.sdk / "src/lib.rs").write_text("#![no_std]\n")
        (self.sdk / "wit").mkdir()
        (self.sdk / "wit/wabrix.wit").write_bytes(WIT)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("add", "Cargo.toml", "wit/wabrix.wit", "src/lib.rs")
        self.git("commit", "--quiet", "-m", "SDK test fixture")

    def run_script(self, *arguments, source=True):
        return subprocess.run(
            [
                sys.executable, str(self.plugin / "scripts/sync_wit.py"),
                *arguments, *(["--source", str(self.sdk)] if source else []),
            ],
            cwd=self.plugin,
            capture_output=True,
            text=True,
            env=self.environment,
        )

    def assert_synced(self, version):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        lock = json.loads((self.plugin / "wit/source.lock.json").read_text())
        self.assertEqual(lock["sdk_version"], version)
        self.assertEqual(lock["revision"], self.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(lock["sha256"], hashlib.sha256(WIT).hexdigest())
        self.assertEqual((self.plugin / "wit/wabrix.wit").read_bytes(), WIT)

    def prepare_check(self, minimum="0.7.0", resolved=None, requirement=None, sdk_wit=None):
        self.commit_sdk(
            f'[package]\nname = "wabrix_api"\nversion = "{minimum}"\nedition = "2021"\n'
        )
        self.assert_synced(minimum)
        if resolved is not None or sdk_wit is not None:
            (self.sdk / "Cargo.toml").write_text(
                f'[package]\nname = "wabrix_api"\nversion = "{resolved or minimum}"\n'
                'edition = "2021"\n'
            )
            if sdk_wit is not None:
                (self.sdk / "wit/wabrix.wit").write_bytes(sdk_wit)
            self.git("add", "Cargo.toml", "wit/wabrix.wit")
            self.git("commit", "--quiet", "-m", "Compatible SDK development")
        # A local Git remote exercises real Cargo resolution without network access.
        lock_path = self.plugin / "wit/source.lock.json"
        lock = json.loads(lock_path.read_text())
        lock["repository"] = self.sdk.as_uri()
        lock_path.write_text(json.dumps(lock))
        (self.plugin / "Cargo.toml").write_text(
            '[package]\nname = "wit-check-fixture"\nversion = "0.1.0"\n'
            'edition = "2021"\n[workspace.dependencies]\n'
            f'wabrix_api = {{ git = "{lock["repository"]}", branch = "main", '
            f'version = "{requirement or minimum}" }}\n'
            '[dependencies]\nwabrix_api.workspace = true\n'
        )
        (self.plugin / "src").mkdir()
        (self.plugin / "src/lib.rs").write_text("#![no_std]\n")
        metadata = self.cargo_metadata()
        return lock, metadata

    def cargo_metadata(self):
        result = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--all-features"],
            cwd=self.plugin, env=self.environment, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def assert_check_failed(self, message):
        result = self.run_script("--check", source=False)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)

    def assert_check_passed(self, source=False):
        result = self.run_script("--check", source=source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_check_uses_cargo_cache_without_separate_sdk_checkout(self):
        self.prepare_check()
        self.sdk.rename(self.sdk.with_name("sdk-unavailable"))
        result = self.run_script("--check", source=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Cargo SDK version(s) 0.7.0 compatible with ^0.7.0", result.stdout)

    def test_check_with_optional_local_source(self):
        self.prepare_check()
        self.assert_check_passed(source=True)
        # Source WIT changes do not affect a version-only compatibility check.
        (self.sdk / "wit/wabrix.wit").write_bytes(WIT + b"// local change\n")
        self.assert_check_passed(source=True)
        manifest = self.sdk / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('"0.7.0"', '"0.8.0"'))
        result = self.run_script("--check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Local SDK version 0.8.0 is incompatible", result.stderr)

    def test_check_accepts_different_commit_and_wit_with_same_sdk_version(self):
        lock, metadata = self.prepare_check(sdk_wit=WIT + b"// SDK development\n")
        resolved = next(p for p in metadata["packages"] if p["name"] == "wabrix_api")
        self.assertNotEqual(resolved["source"].split("#")[-1], lock["revision"])
        self.assert_check_passed()

    def test_check_accepts_compatible_patch_release(self):
        self.prepare_check(resolved="0.7.4")
        result = self.assert_check_passed()
        self.assertIn("Cargo SDK version(s) 0.7.4 compatible with ^0.7.0", result.stdout)

    def test_check_accepts_compatible_minor_release_after_one_point_zero(self):
        self.prepare_check(minimum="1.2.3", resolved="1.8.0")
        self.assert_check_passed()

    def test_check_accepts_multiple_sdk_sources_with_compatible_versions(self):
        lock, _ = self.prepare_check(resolved="0.7.1")
        with (self.plugin / "Cargo.toml").open("a") as manifest:
            manifest.write(
                f'baseline_api = {{ package = "wabrix_api", git = "{lock["repository"]}", '
                f'rev = "{lock["revision"]}" }}\n'
            )
        metadata = self.cargo_metadata()
        versions = {p["version"] for p in metadata["packages"] if p["name"] == "wabrix_api"}
        self.assertEqual(versions, {"0.7.0", "0.7.1"})
        self.assert_check_passed()

    def test_check_rejects_incompatible_additional_sdk_dependency(self):
        self.prepare_check()
        other_sdk = self.sdk.with_name("other-sdk")
        shutil.copytree(self.sdk, other_sdk, ignore=shutil.ignore_patterns(".git"))
        manifest = other_sdk / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('"0.7.0"', '"0.8.0"'))
        with (self.plugin / "Cargo.toml").open("a") as manifest:
            manifest.write(
                f'other_api = {{ package = "wabrix_api", path = "{other_sdk.as_posix()}" }}\n'
            )
        self.cargo_metadata()
        self.assert_check_failed("Cargo-resolved SDK version 0.8.0 is incompatible")

    def test_check_rejects_prerelease_without_opt_in(self):
        self.prepare_check(resolved="0.7.1-alpha", requirement="0.7.1-alpha")
        self.assert_check_failed("Cargo-resolved SDK version 0.7.1-alpha is incompatible")

    def test_check_accepts_prerelease_with_opt_in(self):
        self.prepare_check(minimum="0.7.0-alpha.1", resolved="0.7.0-alpha.2")
        self.assert_check_passed()

    def test_check_ignores_build_metadata(self):
        self.prepare_check(minimum="0.7.0+build.1", resolved="0.7.0+build.2")
        self.assert_check_passed()

    def test_check_rejects_incompatible_sdk_even_with_broad_manifest_requirement(self):
        self.prepare_check(resolved="0.8.0", requirement=">=0.7, <1")
        self.assert_check_failed("Cargo-resolved SDK version 0.8.0 is incompatible")

    def test_check_rejects_sdk_older_than_snapshot(self):
        self.prepare_check(minimum="0.7.3", resolved="0.7.2", requirement="0.7")
        self.assert_check_failed("Cargo-resolved SDK version 0.7.2 is incompatible")

    def test_check_honors_cargo_manifest_requirement(self):
        self.prepare_check()
        manifest = self.plugin / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace(
            'version = "0.7.0"', 'version = "~0.7.1"'
        ))
        self.assert_check_failed("failed to select a version for the requirement")

    def test_check_rejects_changed_snapshot(self):
        self.prepare_check()
        (self.plugin / "wit/wabrix.wit").write_bytes(WIT + b"// changed\n")
        self.assert_check_failed("WIT snapshot differs from source.lock.json")

    def test_check_accepts_compatible_path_patch_without_git_checkout(self):
        lock, _ = self.prepare_check()
        patched_sdk = self.sdk.with_name("patched-sdk")
        shutil.copytree(self.sdk, patched_sdk, ignore=shutil.ignore_patterns(".git"))
        with (self.plugin / "Cargo.toml").open("a") as manifest:
            manifest.write(
                f'\n[patch."{lock["repository"]}"]\n'
                f'wabrix_api = {{ path = "{patched_sdk.as_posix()}" }}\n'
            )
        self.cargo_metadata()
        self.assert_check_passed()

    def test_check_accepts_compatible_cargo_configuration_path_override(self):
        self.prepare_check()
        (self.plugin / ".cargo").mkdir()
        (self.plugin / ".cargo/config.toml").write_text(
            f'paths = ["{self.sdk.as_posix()}"]\n'
        )
        self.assert_check_passed()

    def test_standalone_version_comes_from_committed_manifest(self):
        self.commit_sdk('[package]\nname = "wabrix_api"\nversion = "0.7.0"\n')
        (self.sdk / "Cargo.toml").write_text(
            '[package]\nname = "wabrix_api"\nversion = "99.0.0"\n'
        )
        self.assert_synced("0.7.0")

    def test_legacy_virtual_workspace(self):
        self.commit_sdk('[workspace.package]\nversion = "0.6.1"\n')
        self.assert_synced("0.6.1")

    def test_workspace_package_inherits_version(self):
        self.commit_sdk(
            '[package]\nname = "wabrix_api"\nversion.workspace = true\n'
            '[workspace.package]\nversion = "0.6.1"\n'
        )
        self.assert_synced("0.6.1")

    def test_missing_version_leaves_snapshot_and_lock_unchanged(self):
        self.commit_sdk('[package]\nname = "wabrix_api"\n')
        (self.plugin / "wit").mkdir()
        snapshot = self.plugin / "wit/wabrix.wit"
        lock = self.plugin / "wit/source.lock.json"
        snapshot.write_bytes(b"existing snapshot")
        lock.write_bytes(b"existing lock")
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn("[package] or [workspace.package]", result.stderr)
        self.assertEqual(snapshot.read_bytes(), b"existing snapshot")
        self.assertEqual(lock.read_bytes(), b"existing lock")

    def test_uncommitted_wit_leaves_snapshot_and_lock_unchanged(self):
        self.commit_sdk('[package]\nname = "wabrix_api"\nversion = "0.7.0"\n')
        self.assert_synced("0.7.0")
        lock = self.plugin / "wit/source.lock.json"
        previous_lock = lock.read_bytes()
        (self.sdk / "wit/wabrix.wit").write_bytes(WIT + b"// uncommitted\n")
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn("Commit the canonical SDK WIT changes", result.stderr)
        self.assertEqual((self.plugin / "wit/wabrix.wit").read_bytes(), WIT)
        self.assertEqual(lock.read_bytes(), previous_lock)


class CargoVersionCompatibilityTests(unittest.TestCase):
    def test_caret_compatibility(self):
        cases = [
            ("0.7.0", "0.7.0", True),
            ("0.7.4", "0.7.0", True),
            ("0.8.0", "0.7.0", False),
            ("0.7.2", "0.7.3", False),
            ("0.6.9", "0.7.0", False),
            ("1.8.0", "1.2.3", True),
            ("2.0.0", "1.2.3", False),
            ("1.2.2", "1.2.3", False),
            ("0.0.3", "0.0.3", True),
            ("0.0.4", "0.0.3", False),
            ("0.0.0", "0.0.0", True),
            ("0.0.1", "0.0.0", False),
            ("0.7.0+build.2", "0.7.0+build.1", True),
            ("0.7.0-alpha", "0.7.0", False),
            ("0.7.1-alpha", "0.7.0", False),
            ("0.7.0", "0.7.0-alpha", True),
            ("0.7.1", "0.7.0-alpha", True),
            ("0.7.0-alpha.2", "0.7.0-alpha.1", True),
            ("0.7.0-alpha.10", "0.7.0-alpha.2", True),
            ("0.7.0-alpha.1", "0.7.0-alpha.2", False),
            ("0.7.0-alpha.1", "0.7.0-alpha", True),
            ("0.7.0-alpha", "0.7.0-alpha.1", False),
            ("0.7.0-beta", "0.7.0-alpha", True),
            ("0.7.0-alpha.beta", "0.7.0-alpha.1", True),
            ("0.7.0-alpha.1", "0.7.0-alpha.beta", False),
            ("0.7.1-alpha", "0.7.0-alpha", False),
        ]
        for version, minimum, expected in cases:
            with self.subTest(version=version, requirement="^" + minimum):
                self.assertEqual(compatible_version(version, minimum), expected)

    def test_invalid_versions_fail_clearly(self):
        for version in ("0.7", "01.7.0", "0.7.0-01", "0.7.0+", "not-a-version"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(ValueError, "Invalid SDK SemVer version"):
                    compatible_version(version, "0.7.0")
                with self.assertRaisesRegex(ValueError, "Invalid SDK SemVer version"):
                    compatible_version("0.7.0", version)


if __name__ == "__main__":
    unittest.main()
