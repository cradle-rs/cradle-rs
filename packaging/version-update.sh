#! /bin/bash

# Propagate the top-level `version` file into the workspace Cargo.toml. The
# cradle crate inherits it (version.workspace = true), and cargo-deb reads it
# straight from Cargo.toml, so this is the single place the package version is
# set (the former nfpm-*.yaml version fields are gone).
for file in ../Cargo.toml
do
    sed -i "s/^version = .*/version = \"$(cat ../version)\"/" ${file}
done
