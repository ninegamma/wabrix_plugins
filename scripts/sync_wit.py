#!/usr/bin/env python3
"""Sync or verify the versioned WIT snapshot from the canonical SDK repository."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
WIT_PATH = "wit/wabrix.wit"
LOCK_PATH = ROOT / "wit/source.lock.json"


def git(source: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(source), *arguments])


def verify_sdk_package(package: dict, lock: dict, origin: str) -> None:
    expected_source = (
        f"git+{lock['repository']}?rev={lock['revision']}#{lock['revision']}"
    )
    if package.get("source") != expected_source:
        raise ValueError(
            f"{origin} must resolve wabrix_api from {lock['repository']} at "
            f"{lock['revision']}; found {package.get('source')!r}. "
            "Path/alternate-source overrides cannot verify the pinned SDK. "
            "Update the dependency pin and run cargo update -p wabrix_api."
        )
    if package["version"] != lock["sdk_version"]:
        raise ValueError(f"{origin} SDK version differs from source.lock.json")


def verify_cargo(lock: dict, snapshot: bytes) -> None:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    dependency = manifest["workspace"]["dependencies"]["wabrix_api"]
    if (
        not isinstance(dependency, dict)
        or dependency.get("git") != lock["repository"]
        or dependency.get("rev") != lock["revision"]
        or any(key in dependency for key in ("branch", "tag", "path"))
    ):
        raise ValueError(
            "Cargo.toml workspace dependency wabrix_api must pin "
            f"git = {lock['repository']!r}, rev = {lock['revision']!r}, "
            "matching wit/source.lock.json"
        )

    cargo_lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    packages = [p for p in cargo_lock["package"] if p["name"] == "wabrix_api"]
    if len(packages) != 1:
        raise ValueError("Cargo.lock must contain exactly one resolved wabrix_api package")
    verify_sdk_package(packages[0], lock, "Cargo.lock")

    # Cargo resolves patches/configuration and supplies its downloaded SDK checkout.
    # --locked prevents verification from silently updating the dependency lockfile.
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--all-features"],
        cwd=ROOT,
    ))
    packages = [p for p in metadata["packages"] if p["name"] == "wabrix_api"]
    if len(packages) != 1:
        raise ValueError("Cargo must resolve exactly one wabrix_api package")
    sdk = packages[0]
    verify_sdk_package(sdk, lock, "Cargo metadata")
    sdk_directory = Path(sdk["manifest_path"]).parent
    sdk_root = Path(git(sdk_directory, "rev-parse", "--show-toplevel").decode().strip())
    if git(sdk_root, "rev-parse", "HEAD").decode().strip() != lock["revision"]:
        raise ValueError("Cargo's SDK checkout is not at the pinned revision")
    if snapshot != git(sdk_root, "show", f"{lock['revision']}:{lock['path']}"):
        raise ValueError("WIT snapshot differs from Cargo's pinned SDK revision")
    if snapshot != (sdk_root / lock["path"]).read_bytes():
        raise ValueError("WIT in Cargo's SDK checkout has been modified")


def verify(source: Path | None) -> None:
    lock = json.loads(LOCK_PATH.read_text())
    snapshot = (ROOT / WIT_PATH).read_bytes()
    if hashlib.sha256(snapshot).hexdigest() != lock["sha256"]:
        raise ValueError("WIT snapshot differs from source.lock.json; run scripts/sync_wit.py")
    verify_cargo(lock, snapshot)
    if source is not None:
        upstream = git(source, "show", f"{lock['revision']}:{lock['path']}")
        if snapshot != upstream:
            raise ValueError("WIT snapshot differs from its pinned upstream revision")
        if snapshot != (source / WIT_PATH).read_bytes():
            raise ValueError("SDK WIT has changed; sync the snapshot before building plugins")
    print(f"WIT snapshot and resolved Cargo SDK verified: {lock['revision']}")


def sync(source: Path) -> None:
    revision = git(source, "rev-parse", "HEAD").decode().strip()
    snapshot = git(source, "show", f"{revision}:{WIT_PATH}")
    if snapshot != (source / WIT_PATH).read_bytes():
        raise ValueError("Commit the canonical SDK WIT changes before syncing a versioned snapshot")
    manifest = tomllib.loads(git(source, "show", f"{revision}:Cargo.toml").decode())
    sdk_version = manifest.get("package", {}).get("version")
    if sdk_version is None or sdk_version == {"workspace": True}:
        sdk_version = manifest.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(sdk_version, str) or not sdk_version:
        raise ValueError(
            "SDK Cargo.toml must define a version in [package] or [workspace.package]"
        )
    lock = {
        "repository": "https://github.com/ninegamma/wabrix_api.git",
        "revision": revision,
        "path": WIT_PATH,
        "sdk_version": sdk_version,
        "sha256": hashlib.sha256(snapshot).hexdigest(),
    }
    (ROOT / "wit").mkdir(exist_ok=True)
    (ROOT / WIT_PATH).write_bytes(snapshot)
    LOCK_PATH.write_text(json.dumps(lock, indent=2) + "\n")
    print(f"WIT snapshot synced: {revision}")
    print(
        f"Pin workspace.dependencies.wabrix_api to rev = {revision!r}, then run "
        "cargo update -p wabrix_api and scripts/sync_wit.py --check."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="Verify the snapshot, dependency pin, lockfile, and Cargo-fetched SDK WIT",
    )
    parser.add_argument(
        "--source",
        type=Path,
        help="SDK repository; sync defaults to ../wabrix_api, check optionally verifies upstream too",
    )
    arguments = parser.parse_args()
    try:
        if arguments.check:
            verify(arguments.source)
        else:
            sync(arguments.source or ROOT.parent / "wabrix_api")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"WIT sync failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
