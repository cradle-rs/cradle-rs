//! Compiles the `cradle-ebpf` crate to `bpfel-unknown-none` and drops the
//! resulting object in `OUT_DIR`, where `main.rs` embeds it via
//! `aya::include_bytes_aligned!`.

use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf(
        [Package {
            name: "cradle-ebpf",
            // Used for `cargo:rerun-if-changed`.
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../cradle-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        // `nightly` — required for `-Z build-std=core` against the BPF target.
        Toolchain::default(),
    )?;
    Ok(())
}
