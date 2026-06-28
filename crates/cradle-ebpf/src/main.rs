#![no_std]
#![no_main]

//! cradle-rs eBPF data plane.
//!
//! Phase 0: a TC (`clsact`) classifier skeleton that passes all traffic
//! through. Subsequent phases grow this into a tail-call-staged pipeline:
//! L2 switching (FDB) → L3 forwarding (FIB + neighbor) → L4 load balancing
//! and connection tracking, all driven by the maps defined in `cradle-common`.

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};

#[classifier]
pub fn cradle_tc(ctx: TcContext) -> i32 {
    match try_cradle_tc(&ctx) {
        Ok(act) => act,
        Err(_) => TC_ACT_PIPE as i32,
    }
}

#[inline(always)]
fn try_cradle_tc(_ctx: &TcContext) -> Result<i32, ()> {
    // Phase 0: hand every frame back to the stack untouched.
    Ok(TC_ACT_PIPE as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
