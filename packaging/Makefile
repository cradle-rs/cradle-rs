all: arm64

# Optional explicit package version, e.g. the nightly pipeline passes
# DEB_VERSION=0.9.7~nightly20260715 (env or make var) to override the version
# read from Cargo.toml. Empty for stable builds (the clean Cargo.toml version).
DEB_VERSION ?=
DEB_VERSION_ARG := $(if $(DEB_VERSION),--deb-version "$(DEB_VERSION)",)

# Build the .deb with cargo-deb (config in ../crates/cradle/Cargo.toml,
# [package.metadata.deb]). cargo-deb picks the host architecture, so `amd64`
# and `arm64` are the same recipe run on the matching native runner; both
# targets exist so the CI matrix can name an arch explicitly.
#
# `cargo build --release` builds the default-members (cradle, cradle-cni,
# cradle-k8s — the eBPF crate is built for bpfel-unknown-none by cradle's
# build script); `cargo deb --no-build -p cradle` then packages those three
# prebuilt binaries. The .deb lands here (--output .) as
# cradle-rs_<version>_<arch>.deb (package name overridden to cradle-rs).
arm64 amd64: changelog
	cargo build --release
	cargo deb --no-build -p cradle --output . $(DEB_VERSION_ARG)

# Regenerate the Debian-format changelog cargo-deb ships, from the
# single-source CHANGELOG.yaml (see changelog-gen.sh). Written to out/changelog,
# which ../crates/cradle/Cargo.toml references as `changelog`.
.PHONY: changelog
changelog:
	./changelog-gen.sh

# Preview the GitHub release body rendered from CHANGELOG.yaml's newest entry
# (what nightly.yaml/release.yaml publish, minus the fixed downloads table).
# Pass VERSION=<X.Y.Z> to preview a specific past entry instead of the top one.
# Not part of the .deb build — this feeds the GitHub Releases page, not the package.
.PHONY: release-notes
release-notes:
	./release-notes.sh $(VERSION)
