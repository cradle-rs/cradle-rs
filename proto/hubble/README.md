Vendored Hubble Observer/Flow/Peer protos, copied verbatim from cilium/cilium
v1.19.5 (`api/v1/{observer,flow,relay,peer}/`). cradle serves a subset of the
Observer service and the Peer service (docs/design/hubble.md) so `hubble
observe` works against a cradle node and the stock `hubble-relay` can discover
and aggregate cradle nodes. Compiled by crates/cradle/build.rs with this dir
as the include root, so `import "flow/flow.proto"` resolves.
