Vendored Hubble Observer/Flow protos, copied verbatim from cilium/cilium
v1.19.5 (`api/v1/{observer,flow,relay}/`). cradle serves a subset of the
Observer service (docs/design/hubble.md) so `hubble observe` works against a
cradle node. Compiled by crates/cradle/build.rs with this dir as the include
root, so `import "flow/flow.proto"` resolves.
