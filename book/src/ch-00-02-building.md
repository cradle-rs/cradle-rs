# Building and Running

## Prerequisites

cradle-rs compiles its eBPF data plane with aya, which needs a **nightly** Rust
toolchain (for `-Z build-std=core` against `bpfel-unknown-none`) and the
`bpf-linker`. The whole workspace is pinned to nightly by `rust-toolchain.toml`,
so `rustup` selects it automatically inside the repository.

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

No clang, libbpf, or BTF-generation tooling is required — the Rust toolchain
produces everything the loader needs. A Linux kernel with BTF (5.x+; developed
and tested on 6.8) is required at run time.

## Building

```sh
cargo build            # builds cradle-common + cradle (+ cradle-ebpf via build.rs)
```

The `cradle-ebpf` crate is **not** in `default-members`; it is built for the
eBPF target as a side effect of building `cradle`, whose `build.rs` invokes
`aya-build` and embeds the object. You never build `cradle-ebpf` for the host.

The result is a single binary, `target/debug/cradle`, with the data plane baked
in.

## Running

`cradle` has two subcommands: **`serve`** loads the data plane and (optionally)
applies a bootstrap config and/or serves the gRPC control API; **`ctl`** is the
client that pushes configuration to a running instance. Loading and attaching
eBPF programs needs `CAP_BPF` and `CAP_NET_ADMIN`, so `serve` typically runs as
root.

```sh
# Load the data plane, apply a bootstrap config, and serve the control API.
sudo ./target/debug/cradle serve --config fwd.json --grpc unix:/run/cradle.sock

# From another shell, push more configuration over gRPC.
./target/debug/cradle ctl --grpc unix:/run/cradle.sock apply more.json

# Dump the datapath packet counters.
./target/debug/cradle ctl --grpc unix:/run/cradle.sock stats
```

Both the bootstrap `--config` and `ctl apply` consume the **same JSON config
format**, described in [Configuration Model](ch-01-00-configuration.md). The
difference is only *where* it is applied: `serve --config` applies in-process at
startup; `ctl apply` replays the identical operations over the wire against a
running daemon.

A `serve` with neither `--config` nor `--grpc` just loads the data plane and
waits for Ctrl-C — useful for confirming the object loads and attaches on a given
kernel.

The full option reference is in
[Command Line Options](ch-00-03-command-line-options.md).
