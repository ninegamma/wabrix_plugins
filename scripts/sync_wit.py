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


def verify(source: Path | None) -> None:
    lock = json.loads(LOCK_PATH.read_text())
    snapshot = (ROOT / WIT_PATH).read_bytes()
    if hashlib.sha256(snapshot).hexdigest() != lock["sha256"]:
        raise ValueError("WIT snapshot differs from source.lock.json; run scripts/sync_wit.py")
    if source is not None:
        upstream = git(source, "show", f"{lock['revision']}:{lock['path']}")
        if snapshot != upstream:
            raise ValueError("WIT snapshot differs from its pinned upstream revision")
        if snapshot != (source / WIT_PATH).read_bytes():
            raise ValueError("SDK WIT has changed; sync the snapshot before building plugins")
    print(f"WIT snapshot verified: {lock['revision']}")


def sync(source: Path) -> None:
    revision = git(source, "rev-parse", "HEAD").decode().strip()
    snapshot = git(source, "show", f"{revision}:{WIT_PATH}")
    if snapshot != (source / WIT_PATH).read_bytes():
        raise ValueError("Commit the canonical SDK WIT changes before syncing a versioned snapshot")
    manifest = tomllib.loads(git(source, "show", f"{revision}:Cargo.toml").decode())
    lock = {
        "repository": "https://github.com/ninegamma/wabrix_api.git",
        "revision": revision,
        "path": WIT_PATH,
        "sdk_version": manifest["workspace"]["package"]["version"],
        "sha256": hashlib.sha256(snapshot).hexdigest(),
    }
    (ROOT / "wit").mkdir(exist_ok=True)
    (ROOT / WIT_PATH).write_bytes(snapshot)
    LOCK_PATH.write_text(json.dumps(lock, indent=2) + "\n")
    print(f"WIT snapshot synced: {revision}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify the snapshot without changing files")
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
