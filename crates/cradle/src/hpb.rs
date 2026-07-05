//! Generated Hubble Observer/Flow/Relay gRPC types (vendored Cilium v1.19.5
//! protos, compiled by `build.rs`). The three packages are sibling modules so
//! the cross-package `super::flow::…` / `super::relay::…` references resolve.

#![allow(clippy::all)]
#![allow(missing_docs)]
// Generated protobuf pulls in message types cradle does not use (e.g.
// ExportEvent); their generated structs/oneofs are legitimately dead code.
#![allow(dead_code)]

pub mod flow {
    include!(concat!(env!("OUT_DIR"), "/flow.rs"));
}
pub mod relay {
    include!(concat!(env!("OUT_DIR"), "/relay.rs"));
}
pub mod observer {
    include!(concat!(env!("OUT_DIR"), "/observer.rs"));
}
