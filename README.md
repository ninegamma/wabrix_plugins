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
│   ├── generator_plugin/ # Deprecated; use generator_engine
│   ├── filter_engine/
│   └── inspector_engine/
├── scripts/sync_wit.py
└── wit/                # Versioned snapshot of the SDK interfaces
```


## Dependencies and checkout layout

Plugin developers only need to clone this repository. Cargo downloads
`wabrix_api` from `main`, subject to the version requirement in `Cargo.toml`.
`Cargo.lock` records the selected commit for reproducible builds; use
`cargo update -p wabrix_api` to advance it. The SDK only needs to be compatible
with the version recorded in `wit/source.lock.json`, using Cargo's default caret
rules. For example, snapshot SDK `0.7.0` accepts `0.7.x`, but rejects `0.8.0`.

Maintainers working on the SDK or native host can keep sibling checkouts:

```text
wabrix_prj/
├── wabrix_api/          # Generic SDK and canonical WIT interfaces
├── wabrix_plugins/      # This repository
└── wabrix/              # Native host
```

This workspace has its own package versions, lockfile, build configuration, and
Git history. The sibling SDK checkout is optional for plugin development and is
used by maintainers when updating the canonical WIT. Native host dependencies
currently use both sibling checkouts to share the same SDK types.

The `wabrix_plugins` library exports `tcp_common`, `connections`, and
`engine_common`. Plugins and native nodes use it for the TCP state machine,
connection pool, packet generator, configuration parsing, and engine control.
Generic packet, mailbox, shared-state, opcode, and `EngineTimerPlan` types remain
in `wabrix_api`. Filter and inspector plugins depend directly on that SDK.

## Build and verification

Use Rust/Cargo, Git, Python 3.11 or newer, and a C11 compiler (`cc`, or the
executable selected by `CC`) for the SDK's ABI checks. Network access is needed
to download dependencies initially. Run these commands from this repository:

```bash
rustup target add wasm32-wasip2
python3 scripts/sync_wit.py --check
cargo test --workspace --all-features --locked
cargo build --workspace --release --target wasm32-wasip2 --all-features --locked
cargo clippy --workspace --all-features --target wasm32-wasip2 --locked
```

Plugin components are written to `target/wasm32-wasip2/release/`. The repository's
`.cargo/config.toml` preserves the UMEM memory limits and Wasm stack/export flags.
The default workspace members include the library and all five active plugins,
so `cargo build --release --target wasm32-wasip2` also builds them all.

The WIT check verifies the snapshot checksum and uses `cargo metadata --locked`
to check the resolved SDK's version, including dependency overrides. Compatible
SDK commits, WIT contents, and local path dependencies are allowed. Cargo can
download missing dependencies; no separate SDK checkout is needed. See
[wit/README.md](wit/README.md) for offline checks and the interface update workflow.
For breaking interface changes, follow the
[SDK, plugins, and host migration sequence](https://github.com/ninegamma/wabrix_api/blob/main/wit_breaking_change.md).

## Generator plugin deprecation

`generator_plugin.wasm` and its `generator-plugin` WIT world are deprecated and
will be removed in one of the next versions. Replace it with
`generator_engine.wasm`, which implements the `engine-plugin` world. Adapt the
host node configuration and startup parameters to its timer/mailbox interface;
see the [SDK migration guide](https://github.com/ninegamma/wabrix_api/blob/main/wit_doc.md#generator-plugin-deprecation-and-migration).

Build the replacement with:

```bash
cargo build -p generator_engine --release --target wasm32-wasip2 --locked
```

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
