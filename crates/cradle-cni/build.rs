//! Build script: compile the shared cradle control-API proto (the plugin is a
//! gRPC client of the cradle daemon).

fn main() -> anyhow::Result<()> {
    // The build script runs in the crate dir, so reference the workspace-root
    // proto by absolute path.
    tonic_prost_build::compile_protos(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../proto/cradle.proto"
    ))?;
    Ok(())
}
