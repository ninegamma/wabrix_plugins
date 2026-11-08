#!/usr/bin/env python3
"""Sync or verify the versioned WIT snapshot from the canonical SDK repository."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
WIT_PATH = "wit/wabrix.wit"
LOCK_PATH = ROOT / "wit/source.lock.json"


def git(source: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(source), *arguments])


def parse_version(version: str) -> tuple[tuple[int, ...], tuple[str, ...]]:
    match = re.fullmatch(
        r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
        r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
        version,
    )
    if match is None:
        raise ValueError(f"Invalid SDK SemVer version: {version!r}")
    core = tuple(int(part) for part in match.group(1, 2, 3))
    prerelease = tuple(match[4].split(".")) if match[4] else ()
    if any(part > 2**64 - 1 for part in core) or any(
        part.isdigit() and len(part) > 1 and part.startswith("0")
        for part in prerelease
    ):
        raise ValueError(f"Invalid SDK SemVer version: {version!r}")
    return core, prerelease


def compatible_version(version: str, minimum: str) -> bool:
    """Match Cargo's implicit caret requirement for a complete SDK version.

    Cargo itself checks arbitrary requirements from Cargo.toml via metadata.
    Here the snapshot records one version, interpreted as ^major.minor.patch.
    """
    core, prerelease = parse_version(version)
    required, required_prerelease = parse_version(minimum)
    # Caret compatibility preserves all components through the first nonzero one.
    fixed = next((index + 1 for index, part in enumerate(required) if part), 3)
    if core < required or core[:fixed] != required[:fixed]:
        return False
    if not prerelease:
        return True
    # Cargo only admits prereleases explicitly opted into for the same core.
    if not required_prerelease or core != required:
        return False
    for actual, expected in zip(prerelease, required_prerelease):
        if actual == expected:
            continue
        if actual.isdigit() and expected.isdigit():
            return int(actual) > int(expected)
        if actual.isdigit() != expected.isdigit():
            return not actual.isdigit()
        return actual > expected
    return len(prerelease) >= len(required_prerelease)


def verify_sdk_version(version: str, minimum: str, origin: str) -> None:
    if not compatible_version(version, minimum):
        raise ValueError(
            f"{origin} SDK version {version} is incompatible with the WIT "
            f"snapshot's Cargo requirement ^{minimum}"
        )


def sdk_version(manifest: dict) -> str:
    version = manifest.get("package", {}).get("version")
    if version is None or version == {"workspace": True}:
        version = manifest.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(
            "SDK Cargo.toml must define a version in [package] or [workspace.package]"
        )
    parse_version(version)
    return version


def verify_cargo(lock: dict) -> str:
    # Cargo enforces the manifest's version requirements, including patches and
    # configuration overrides. --locked keeps verification from updating files.
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--all-features"],
        cwd=ROOT,
    ))
    packages = [p for p in metadata["packages"] if p["name"] == "wabrix_api"]
    if not packages:
        raise ValueError("Cargo does not resolve a wabrix_api package")
    versions = sorted({package["version"] for package in packages})
    for version in versions:
        verify_sdk_version(version, lock["sdk_version"], "Cargo-resolved")
    return ", ".join(versions)


def verify(source: Path | None) -> None:
    lock = json.loads(LOCK_PATH.read_text())
    snapshot = (ROOT / WIT_PATH).read_bytes()
    if hashlib.sha256(snapshot).hexdigest() != lock["sha256"]:
        raise ValueError("WIT snapshot differs from source.lock.json; run scripts/sync_wit.py")
    version = verify_cargo(lock)
    if source is not None:
        local_version = sdk_version(tomllib.loads((source / "Cargo.toml").read_text()))
        verify_sdk_version(local_version, lock["sdk_version"], "Local")
    print(
        f"WIT snapshot verified; Cargo SDK version(s) {version} compatible with "
        f"^{lock['sdk_version']}"
    )


def sync(source: Path) -> None:
    revision = git(source, "rev-parse", "HEAD").decode().strip()
    snapshot = git(source, "show", f"{revision}:{WIT_PATH}")
    if snapshot != (source / WIT_PATH).read_bytes():
        raise ValueError("Commit the canonical SDK WIT changes before syncing a versioned snapshot")
    manifest = tomllib.loads(git(source, "show", f"{revision}:Cargo.toml").decode())
    version = sdk_version(manifest)
    lock = {
        "repository": "https://github.com/ninegamma/wabrix_api.git",
        "revision": revision,
        "path": WIT_PATH,
        "sdk_version": version,
        "sha256": hashlib.sha256(snapshot).hexdigest(),
    }
    (ROOT / "wit").mkdir(exist_ok=True)
    (ROOT / WIT_PATH).write_bytes(snapshot)
    LOCK_PATH.write_text(json.dumps(lock, indent=2) + "\n")
    print(f"WIT snapshot synced: {revision}")
    print(
        f"SDK compatibility requirement: ^{version}. Adjust the workspace SDK "
        "version requirement if needed, then run scripts/sync_wit.py --check."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="Verify the snapshot checksum and Cargo-compatible SDK versions",
    )
    parser.add_argument(
        "--source",
        type=Path,
        help="SDK repository; sync defaults to ../wabrix_api, check also checks its SDK version",
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
