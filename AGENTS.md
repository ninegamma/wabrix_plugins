# Wabrix Plugins

This repository is an independent Cargo workspace. The root package is the
`no_std` `wabrix_plugins` library. Active Wasm component crates live in `plugins/`.
`plugins/inspector_engine_new/` is a preserved prototype outside the workspace.

## Boundaries

- `src/tcp_common.rs`: TCP state machine, generator/config types, packet writers,
  and TCP telemetry.
- `src/connections.rs`: TCP connection pool and timeout tracking.
- `src/engine_common.rs`: Configuration parsing, control handling, and Wasm state
  containers shared by engine plugins.
- `plugins/`: WIT adapters for TCP, generation, filtering, and inspection.
- `wit/wabrix.wit`: Versioned snapshot of the canonical SDK interface.

Dependencies flow from plugin crates to `wabrix_plugins` and `wabrix_api`, and
from `wabrix_plugins` to `wabrix_api`. Never introduce a reverse dependency.
Generic shared-memory layouts, packet/mailbox APIs, shared state, control
opcodes, and `EngineTimerPlan` belong in the sibling `wabrix_api` repository.

## Constraints

- Rust edition 2021. Keep the shared library and dependencies `no_std` compatible.
- Compile plugins as `cdylib` for `wasm32-wasip2`.
- The `generator-plugin` world and `generator_plugin.wasm` are deprecated for
  removal in an upcoming version. Use `generator_engine.wasm` and the
  `engine-plugin` world for new generators.
- Use `wit-bindgen` and the matching WIT world. Never hand-code or silently change
  the ABI. Update canonical WIT in the SDK, commit it there, then run
  `python3 scripts/sync_wit.py`; pin the workspace SDK dependency to the same
  revision and update `Cargo.lock`. Commit both snapshot files and both Cargo
  files together. Publish the SDK commit before others need to fetch it.
- Never enable the SDK `host` feature in a plugin.
- Plugin state is initialized in `init-data`. Wasm instances are single-threaded;
  use existing state containers or `spin::Mutex`, never OS threads or `std::net`.
- No per-packet heap allocations, panics, or dynamic dispatch on batch/timer hot
  paths. A single pre-sized batch allocation is acceptable. Keep cold-path
  configuration and allocations outside those loops.
- Parse packets before reading header offsets, either locally or through an
  explicit upstream FastParse contract. Prefer fingerprints for protocol tests.
- Every new unsafe block needs a preceding `// SAFETY:` proof covering memory
  bounds, validity, and aliasing. Restrict unsafe work to packet/shared-memory
  access and existing low-level internals.
- Preserve packet ownership and routing results; record explicit drop outcomes
  and counters instead of silently discarding packets.
- Do not change fundamental layouts or interfaces beyond the requested scope.
- Preserve the Wasm memory, stack, and export settings in `.cargo/config.toml`.

## Verification

```bash
python3 scripts/sync_wit.py --check
cargo test --workspace --all-features --locked
cargo clippy -p wabrix_plugins --all-targets --locked
cargo clippy --workspace --all-features --target wasm32-wasip2 --locked
cargo build --workspace --release --target wasm32-wasip2 --all-features --locked
```

The SDK has an existing Clippy warning backlog; introduce no new warnings and
do not add lint suppressions without explaining why they are unavoidable.
Explain hot-path performance effects when changing processing logic. Keep diffs
focused and retain WIT compatibility.
