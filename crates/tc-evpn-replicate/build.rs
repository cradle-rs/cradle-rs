//! Build script: compile the `tc-evpn-replicate-ebpf` crate to
//! `bpfel-unknown-none` and emit the object into `OUT_DIR`, where `main.rs`
//! embeds it via `include_bytes_aligned!`. `Toolchain::default()` resolves to
//! `nightly`, and aya-build invokes it with `-Z build-std=core`. Mirrors
//! `cradle`'s build.rs.

use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf(
        [Package {
            name: "tc-evpn-replicate-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../tc-evpn-replicate-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )?;
    Ok(())
}
