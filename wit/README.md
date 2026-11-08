# WIT interface snapshot

`wabrix.wit` is generated from the canonical `wabrix_api` repository. The
upstream Git revision, SDK version, source path, and SHA-256 checksum are
recorded in `source.lock.json`. The workspace's `wabrix_api` dependency is pinned
to that same revision in `Cargo.toml` and `Cargo.lock`.

Verify the committed snapshot without needing an SDK checkout:

```bash
python3 scripts/sync_wit.py --check
```

This verifies the snapshot checksum, the manifest's Git revision pin, the
lockfile's SDK source and version, and Cargo's actual resolved SDK dependency.
It also compares the snapshot with the canonical WIT in Cargo's downloaded SDK
checkout. Mismatched revisions, modified WIT, and path or alternate-source
overrides fail the check. It uses `cargo metadata --locked --all-features`:
project files stay unchanged, but Cargo can populate its dependency cache.
It does not check the latest GitHub branch; it verifies the pinned commit.

Prerequisites are Python 3.11 or newer, Rust/Cargo, Git, and initial network
access to fetch dependencies. Once all dependencies are cached, verify offline:

```bash
CARGO_NET_OFFLINE=true python3 scripts/sync_wit.py --check
```

Maintainers can additionally compare with a sibling SDK checkout, including its
current WIT contents. The same Cargo checks still run:

```bash
python3 scripts/sync_wit.py --check --source ../wabrix_api
```

After committing an interface change in the SDK repository, update the snapshot:

```bash
python3 scripts/sync_wit.py --source ../wabrix_api
```

Set `workspace.dependencies.wabrix_api.rev` in `Cargo.toml` to the revision
printed by the sync command, keeping the Git URL from `source.lock.json`. Push
that SDK commit to its remote so Cargo and other developers can fetch it. Then:

```bash
cargo update -p wabrix_api
python3 scripts/sync_wit.py --check
```

Commit `Cargo.toml`, `Cargo.lock`, `wit/wabrix.wit`, and `wit/source.lock.json`
together. Syncing intentionally leaves dependency updates to this explicit
step; `--check` rejects any mismatch until all four files agree.

Edit the canonical SDK interface first. The sync tool rejects uncommitted WIT
changes so every snapshot refers to an exact upstream revision. Plugin bindings
read this local snapshot; Cargo downloads the matching SDK dependency.

The SDK version is read from the pinned commit's `Cargo.toml`. The tool supports
the standalone SDK's `[package].version` and the former
`[workspace.package].version`, including workspace-inherited package versions.

Run the sync tool's regression tests from the plugin repository root. They use
temporary local Git repositories and Cargo caches, with no network access:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
```
