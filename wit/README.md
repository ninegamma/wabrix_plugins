# WIT interface snapshot

For coordinated changes to the component contract, follow
[Making a breaking WIT API change](https://github.com/ninegamma/wabrix_api/blob/main/wit_breaking_change.md).

`wabrix.wit` is generated from the canonical `wabrix_api` repository. The
upstream Git revision, SDK version, source path, and SHA-256 checksum are
recorded in `source.lock.json`. The Git revision records the snapshot's origin;
it does not constrain the SDK dependency to that commit.

Verify the committed snapshot without needing an SDK checkout:

```bash
python3 scripts/sync_wit.py --check
```

This verifies the snapshot checksum and checks that Cargo's actual resolved SDK
version satisfies the default caret requirement formed from `sdk_version` in
`source.lock.json`. Cargo also enforces the dependency requirements declared in
`Cargo.toml`, including ranges, tilde requirements, and exact versions.

| Snapshot SDK version | Accepted resolved versions | Rejected examples |
| --- | --- | --- |
| `0.7.0` | `>=0.7.0, <0.8.0` | `0.6.9`, `0.8.0` |
| `0.7.3` | `>=0.7.3, <0.8.0` | `0.7.2`, `0.8.0` |
| `0.0.3` | `0.0.3` | `0.0.4` |
| `1.2.3` | `>=1.2.3, <2.0.0` | `1.2.2`, `2.0.0` |

Build metadata does not affect compatibility. Prereleases follow Cargo's opt-in
rules: a stable snapshot version does not accept a prerelease SDK.

Different SDK commits, SDK WIT contents, Git branches/tags, and compatible path
patches are allowed. The check does not compare the SDK's WIT with the snapshot.
Compatibility relies on SDK versioning: breaking WIT/API changes must also bump
the SDK to a breaking version. The snapshot's own checksum still detects edits
that have not been synchronized from the canonical interface.

The check uses `cargo metadata --locked --all-features`: project files stay
unchanged, but Cargo can populate its dependency cache. It verifies the currently
locked dependency; it does not automatically advance to the latest SDK commit.

Prerequisites are Python 3.11 or newer, Rust/Cargo, Git, and initial network
access to fetch dependencies. Once all dependencies are cached, verify offline:

```bash
CARGO_NET_OFFLINE=true python3 scripts/sync_wit.py --check
```

Maintainers can additionally check the version in a sibling SDK checkout's
current `Cargo.toml`. The same Cargo checks still run; neither the local Git
revision nor its WIT contents need to match the snapshot:

```bash
python3 scripts/sync_wit.py --check --source ../wabrix_api
```

After committing an interface change in the SDK repository, update the snapshot:

```bash
python3 scripts/sync_wit.py --source ../wabrix_api
```

Keep the workspace dependency on the development branch, with an appropriate
Cargo version requirement. For example:

```toml
wabrix_api = { git = "https://github.com/ninegamma/wabrix_api.git", branch = "main", version = "0.7" }
```

Adjust `version` if a new compatibility series is required. Publish SDK changes
on the selected branch before consumers update their dependency. To select a
newer compatible SDK commit and verify it:

```bash
cargo update -p wabrix_api
python3 scripts/sync_wit.py --check
```

Commit the snapshot and provenance lock together, plus any changed Cargo files.
`Cargo.lock` retains Cargo's selected commit for reproducibility; that commit
does not have to equal the snapshot's provenance revision.

Edit the canonical SDK interface first. The sync tool rejects uncommitted WIT
changes so every snapshot records a committed upstream origin. Plugin bindings
read this local snapshot; Cargo downloads a version-compatible SDK dependency.

During sync, the SDK version is read from the source commit's `Cargo.toml`. The tool supports
the standalone SDK's `[package].version` and the former
`[workspace.package].version`, including workspace-inherited package versions.

Run the sync tool's regression tests from the plugin repository root. They use
temporary local Git repositories and Cargo caches, with no network access:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
```
