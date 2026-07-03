//! `cradle fib-bench` — the large-FIB lookup-latency harness
//! (`docs/design/large-fib.md`): measures the TC datapath's per-packet cost
//! via `BPF_PROG_TEST_RUN` with the FIB populated at a chosen scale, LPM vs
//! DIR-24-8. Root-only, self-contained (no interfaces, no attach): the
//! test-run skb's `ingress_ifindex` defaults to 0, so a `PORTS[0]` entry
//! sends the packet down the full L3 path.
//!
//! Not CI-gating by design — these are the numbers that justify the FIB
//! engine choice, refreshed by hand.
//!
//! Measurement note: `repeat` re-runs the program on the *same* skb, so the
//! IP TTL exhausts after 63 forwards and every later iteration takes the
//! TTL<=1 exit (retval TC_ACT_PIPE) — *after* the FIB lookup and nexthop
//! resolve. The steady state therefore measures parse + FIB lookup +
//! nexthop resolve with a constant epilogue and no `bpf_redirect_neigh`
//! noise: exactly the engine comparison wanted. The per-category hit
//! counters printed at the end prove every probe resolved in the intended
//! table.

use std::net::Ipv4Addr;
use std::os::fd::{AsFd as _, AsRawFd as _};

use anyhow::{bail, Context as _, Result};
use aya::programs::SchedClassifier;
use cradle_common::{DIR24_TBL8_GROUPS, PORT_F_L3};
use nix::libc;

use crate::{dataplane::Dataplane, util};

/// `bpf(2)` command number for BPF_PROG_TEST_RUN.
const BPF_PROG_TEST_RUN: libc::c_int = 10;

/// The `test` member of `union bpf_attr` (kernel 6.8 layout, verified from
/// the installed uapi headers). Passing our (smaller) size is fine — the
/// kernel only requires trailing bytes of the union to be zero.
#[repr(C)]
#[derive(Default)]
struct BpfAttrTestRun {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    /// Output: average ns per run over `repeat` iterations.
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
}

/// Run the program `repeat` times over `packet`; returns `(retval, avg_ns)`.
fn test_run(prog_fd: i32, packet: &[u8], repeat: u32) -> Result<(u32, u32)> {
    let mut attr = BpfAttrTestRun {
        prog_fd: prog_fd as u32,
        data_size_in: packet.len() as u32,
        data_in: packet.as_ptr() as u64,
        repeat,
        ..Default::default()
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_TEST_RUN,
            &mut attr as *mut _ as *mut libc::c_void,
            core::mem::size_of::<BpfAttrTestRun>(),
        )
    };
    if ret != 0 {
        bail!(
            "BPF_PROG_TEST_RUN failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok((attr.retval, attr.duration))
}

/// A minimal 64-byte Eth + IPv4 + UDP frame to `dst` (valid header checksum,
/// TTL 64) — what the L3 path expects to route.
fn udp_packet(dst: Ipv4Addr) -> [u8; 64] {
    let mut p = [0u8; 64];
    p[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst MAC
    p[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src MAC
    p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    p[14] = 0x45; // v4, IHL 5
    let total_len = (64 - 14) as u16;
    p[16..18].copy_from_slice(&total_len.to_be_bytes());
    p[22] = 64; // TTL
    p[23] = 17; // UDP
    p[26..30].copy_from_slice(&[192, 0, 2, 1]); // src IP
    p[30..34].copy_from_slice(&dst.octets());
    // IPv4 header checksum over bytes 14..34.
    let mut sum = 0u32;
    for i in (14..34).step_by(2) {
        sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p[34..36].copy_from_slice(&1000u16.to_be_bytes()); // sport
    p[36..38].copy_from_slice(&2000u16.to_be_bytes()); // dport
    p[38..40].copy_from_slice(&(total_len - 20).to_be_bytes()); // UDP len
    p
}

/// Probe addresses per category.
const K: usize = 16;

struct Category {
    name: &'static str,
    addrs: Vec<Ipv4Addr>,
}

/// Load the datapath in `dir24`-or-LPM mode, populate `n_routes` DFZ-shaped
/// prefixes (+ 16 host routes for the two-lookup category, + a default
/// route), and measure each probe category.
fn run_mode(dir24: bool, n_routes: u64, seed: u64, repeat: u32) -> Result<()> {
    let mode = if dir24 { "dir24" } else { "lpm" };

    let mut loader = aya::EbpfLoader::new();
    if dir24 {
        loader
            .map_max_entries("TBL24", 1 << 24)
            .map_max_entries("TBL8", DIR24_TBL8_GROUPS * 256);
    } else {
        // The LPM trie is declared at 4096; give it room for the bench table.
        loader.map_max_entries("FIB4", n_routes as u32 + 1024);
    }
    let mut bpf = loader
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/cradle-ebpf"
        )))
        .context("loading eBPF object")?;
    {
        let prog: &mut SchedClassifier = bpf
            .program_mut("cradle_tc")
            .context("program cradle_tc not found")?
            .try_into()?;
        prog.load().context("loading cradle_tc")?;
    }
    let mut dp = Dataplane::from_ebpf(&mut bpf)?;
    if dir24 {
        dp.set_fib4_mode_dir24()?;
    }

    // ingress_ifindex 0 = the test-run default; nexthop oif 1 (lo) — the
    // redirect target never actually transmits under test_run.
    dp.port_set(0, [2, 0, 0, 0, 0, 2], PORT_F_L3, 0, 0)?;
    dp.nexthop_set(1, Some(Ipv4Addr::new(198, 51, 100, 1)), 1, &[], 0)?;
    dp.route4_add(0, Ipv4Addr::UNSPECIFIED, 0, 1, 0)?; // default route

    let prefixes = util::gen_dfz_prefixes(n_routes, seed);
    let routes: Vec<(u32, Ipv4Addr, u8, u32, u32)> = prefixes
        .iter()
        .map(|&(addr, len)| (0u32, Ipv4Addr::from(addr), len, 1u32, 0u32))
        .collect();
    // Time the map install only (generation excluded): LPM = one trie
    // insert per route; dir24 = expansion-engine plan + per-slot writes.
    let start = std::time::Instant::now();
    dp.route4_add_bulk(&routes)?;
    // Host routes: in dir24 mode each claims a TBL8 group (two-lookup path).
    let mut host_addrs = Vec::with_capacity(K);
    for i in 0..K {
        let a = Ipv4Addr::new(91, 0, i as u8, 10);
        dp.route4_add(0, a, 32, 1, 0)?;
        host_addrs.push(a);
    }
    let load = start.elapsed();
    println!(
        "# {mode}: {} routes loaded in {:.2?}",
        n_routes + K as u64,
        load
    );

    let categories = [
        Category {
            name: "direct",
            addrs: prefixes
                .iter()
                .filter(|&&(_, len)| len == 24)
                .take(K)
                .map(|&(addr, _)| Ipv4Addr::from(addr | 7))
                .collect(),
        },
        Category {
            name: "tbl8",
            addrs: host_addrs,
        },
        Category {
            name: "default",
            addrs: (0..K).map(|i| Ipv4Addr::new(99, 1, i as u8, 1)).collect(),
        },
    ];

    let prog: &SchedClassifier = bpf
        .program("cradle_tc")
        .context("program cradle_tc not found")?
        .try_into()?;
    let fd = prog.fd()?.as_fd().as_raw_fd();

    for cat in &categories {
        let mut durs = Vec::with_capacity(cat.addrs.len());
        let mut retvals = std::collections::BTreeSet::new();
        for &addr in &cat.addrs {
            let pkt = udp_packet(addr);
            let (retval, ns) = test_run(fd, &pkt, repeat)?;
            durs.push(ns);
            retvals.insert(retval);
        }
        let avg = durs.iter().map(|&d| d as u64).sum::<u64>() / durs.len() as u64;
        let min = durs.iter().min().unwrap();
        let max = durs.iter().max().unwrap();
        println!(
            "{mode:6} {n_routes:>8} {:<8} avg {avg:>5} ns  min {min:>5}  max {max:>5}  retval {retvals:?}",
            cat.name
        );
    }
    // Validation: which datapath exit the probes took (l3v4_forward counts
    // packets that reached the redirect; a fib-miss would punt earlier).
    let stats = dp.stats()?;
    println!(
        "# {mode}: l3v4_forward={} fib4_vrf_hit={} tbl24_hit={} tbl8_hit={} default={} drop={}",
        stats[cradle_common::STAT_L3V4_FORWARD as usize],
        stats[cradle_common::STAT_FIB4_VRF_HIT as usize],
        stats[cradle_common::STAT_FIB4_TBL24_HIT as usize],
        stats[cradle_common::STAT_FIB4_TBL8_HIT as usize],
        stats[cradle_common::STAT_FIB4_DEFAULT as usize],
        stats[cradle_common::STAT_DROP as usize],
    );
    Ok(())
}

pub fn run(mode: Option<crate::Fib4Mode>, routes: u64, seed: u64, repeat: u32) -> Result<()> {
    match mode {
        Some(crate::Fib4Mode::Lpm) => run_mode(false, routes, seed, repeat),
        Some(crate::Fib4Mode::Dir24) => run_mode(true, routes, seed, repeat),
        None => {
            run_mode(false, routes, seed, repeat)?;
            run_mode(true, routes, seed, repeat)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_layout() {
        let p = udp_packet(Ipv4Addr::new(10, 0, 2, 1));
        assert_eq!(&p[12..14], &[0x08, 0x00]); // EtherType IPv4
        assert_eq!(p[14], 0x45);
        assert_eq!(p[22], 64); // TTL
        assert_eq!(&p[30..34], &[10, 0, 2, 1]); // dst
                                                // Header checksum validates: sum over the header including the
                                                // checksum field must be 0xffff.
        let mut sum = 0u32;
        for i in (14..34).step_by(2) {
            sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum, 0xffff);
    }
}
