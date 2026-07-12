//! Build script: (1) compile the gRPC control API proto, and (2) compile the
//! `cradle-ebpf` crate to `bpfel-unknown-none` (embedded by `main.rs`).

use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    // gRPC control API. The build script runs in the crate dir, so reference
    // the workspace-root proto by absolute path. Emit rerun-if-changed
    // explicitly — the proto lives outside this crate's package dir, so cargo
    // wouldn't otherwise re-run this script (and regenerate the bindings) when
    // it changes.
    println!(
        "cargo:rerun-if-changed={}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto/cradle.proto")
    );
    tonic_prost_build::compile_protos(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../proto/cradle.proto"
    ))?;

    // Hubble Observer + Peer API (docs/design/hubble.md). `proto/hubble` is the
    // include root so `import "flow/flow.proto"` resolves; observer.proto
    // pulls in flow.proto + relay.proto. peer.proto (H3, Relay discovery) is
    // standalone.
    let hubble = concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto/hubble");
    tonic_prost_build::configure().compile_protos(
        &[
            format!("{hubble}/observer/observer.proto"),
            format!("{hubble}/peer/peer.proto"),
        ],
        &[hubble.to_string()],
    )?;

    // eBPF data plane.
    aya_build::build_ebpf(
        [Package {
            name: "cradle-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../cradle-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )?;
    Ok(())
}
