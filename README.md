# Wabrix Plugins

This independent Cargo workspace contains the `no_std` `wabrix_plugins` library
and the WebAssembly plugins for the Wabrix data plane.

```text
wabrix_plugins/
├── Cargo.toml          # Library package and workspace
├── src/                # TCP, connections, generation, and engine control
├── plugins/
│   ├── tcp_engine/
│   ├── generator_engine/
│   ├── generator_plugin/
│   ├── filter_engine/
│   └── inspector_engine/
├── scripts/sync_wit.py
└── wit/                # Versioned snapshot of the SDK interfaces
```


## Dependencies and checkout layout

Keep the SDK and plugin repositories alongside the native host:

```text
wabrix_prj/
├── wabrix_api/          # Generic SDK and canonical WIT interfaces
├── wabrix_plugins/      # This repository
└── wabrix/              # Native host
```

The workspace depends on the standalone `../wabrix_api` package, with SDK version `0.6.1`.
It has its own package versions, lockfile, build configuration, and Git history.
After publishing the SDK changes, the workspace dependency can instead use the
SDK Git repository at a compatible release or revision. Native host dependencies
currently use both sibling checkouts to share the same SDK types.

The `wabrix_plugins` library exports `tcp_common`, `connections`, and
`engine_common`. Plugins and native nodes use it for the TCP state machine,
connection pool, packet generator, configuration parsing, and engine control.
Generic packet, mailbox, shared-state, opcode, and `EngineTimerPlan` types remain
in `wabrix_api`. Filter and inspector plugins depend directly on that SDK.

## Build and verification

Run these commands from this repository:

```bash
rustup target add wasm32-wasip2
python3 scripts/sync_wit.py --check --source ../wabrix_api
cargo test --workspace --all-features --locked
cargo build --workspace --release --target wasm32-wasip2 --all-features --locked
cargo clippy --workspace --all-features --target wasm32-wasip2 --locked
```

Plugin components are written to `target/wasm32-wasip2/release/`. The repository's
`.cargo/config.toml` preserves the UMEM memory limits and Wasm stack/export flags.
The default workspace members include the library and all five active plugins,
so `cargo build --release --target wasm32-wasip2` also builds them all.

The WIT snapshot is pinned by upstream Git revision and checksum. See
[wit/README.md](wit/README.md) for the interface update workflow.

## Generator runtime diagnostics

`generator_engine` has an optional `runtime-diagnostics` feature for investigating
timer-based rate control. It adds completion-time counters, credited cycles,
requested frames, timer timestamps, cycle accumulator values, and histograms.

```bash
cargo build -p generator_engine --release --target wasm32-wasip2 \
  --features runtime-diagnostics
```

It is disabled by default. Host timer summaries are controlled separately by
the native host's `runtime-diagnostics` feature.

## License

MIT; see [LICENSE](LICENSE).
