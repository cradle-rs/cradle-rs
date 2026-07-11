//! Small helpers: resolve interface names, parse MACs and IPv4 prefixes,
//! and the synthetic-DFZ route generator shared by `ctl gen-routes` and
//! `fib-bench`.

use std::{
    collections::HashSet,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context as _, Result, anyhow, bail};

/// Deterministic SplitMix64.
pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Generate `count` distinct synthetic IPv4 prefixes with a DFZ-like
/// prefix-length distribution (deterministic per seed). Addresses are spread
/// over 20.0.0.0–89.255.255.255 — away from the RFC1918 space the tests use
/// and from 99.0.0.0/8 (the DEFAULT4 probe space); only lengths /16../24 are
/// emitted (a real DFZ propagates almost nothing longer than /24).
pub fn gen_dfz_prefixes(count: u64, seed: u64) -> Vec<(u32, u8)> {
    // Cumulative per-mille weights, roughly the public-DFZ histogram.
    const LENS: [(u8, u32); 9] = [
        (24, 620),
        (23, 740),
        (22, 860),
        (21, 920),
        (20, 960),
        (19, 985),
        (18, 995),
        (17, 998),
        (16, 1000),
    ];
    let mut rng = seed;
    let mut seen: HashSet<(u32, u8)> = HashSet::new();
    let mut out = Vec::with_capacity(count as usize);
    while (out.len() as u64) < count {
        let r = splitmix64(&mut rng);
        let dice = (r % 1000) as u32;
        let len = LENS.iter().find(|&&(_, cum)| dice < cum).unwrap().0;
        let mask = u32::MAX << (32 - len as u32);
        let addr = (((20 + (r >> 10) % 70) as u32) << 24 | (r >> 17) as u32 & 0x00ff_ffff) & mask;
        if seen.insert((addr, len)) {
            out.push((addr, len));
        }
    }
    out
}

/// Resolve an interface name to its kernel ifindex via sysfs.
pub fn ifindex_of(name: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{name}/ifindex");
    let s = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    s.trim()
        .parse()
        .with_context(|| format!("parsing ifindex from {path}"))
}

/// Read an interface's MAC address via sysfs.
pub fn mac_of(name: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{name}/address");
    let s = fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    parse_mac(s.trim())
}

/// Parse `aa:bb:cc:dd:ee:ff` into 6 bytes.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut n = 0usize;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            bail!("too many octets in MAC {s:?}");
        }
        mac[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("bad MAC octet {part:?} in {s:?}"))?;
        n += 1;
    }
    if n != 6 {
        bail!("expected 6 octets in MAC {s:?}, got {n}");
    }
    Ok(mac)
}

/// Encode an IPv4 address the way the data plane reads it: a `u32` whose native
/// (little-endian) bytes are the network octets — i.e. exactly what
/// `ctx.load::<u32>()` produces in the eBPF program.
pub fn ipv4_to_map(a: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(a.octets())
}

/// Encode a port the way the data plane reads it: the wire (network-order) bytes
/// read back as a native `u16`.
pub fn port_to_map(p: u16) -> u16 {
    p.to_be()
}

/// Parse `a.b.c.d/len` into an address and prefix length.
pub fn parse_ipv4_prefix(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, len) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("missing '/' in prefix {s:?}"))?;
    let addr: Ipv4Addr = addr.parse().with_context(|| format!("bad IPv4 {addr:?}"))?;
    let len: u8 = len
        .parse()
        .with_context(|| format!("bad prefix length {len:?}"))?;
    if len > 32 {
        bail!("IPv4 prefix length {len} > 32");
    }
    Ok((addr, len))
}

/// Parse `addr/len` into an IPv6 address and prefix length.
pub fn parse_ipv6_prefix(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, len) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("missing '/' in prefix {s:?}"))?;
    let addr: Ipv6Addr = addr.parse().with_context(|| format!("bad IPv6 {addr:?}"))?;
    let len: u8 = len
        .parse()
        .with_context(|| format!("bad prefix length {len:?}"))?;
    if len > 128 {
        bail!("IPv6 prefix length {len} > 128");
    }
    Ok((addr, len))
}
