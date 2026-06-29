//! Small helpers: resolve interface names, parse MACs and IPv4 prefixes.

use std::{fs, net::Ipv4Addr};

use anyhow::{anyhow, bail, Context as _, Result};

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
    let len: u8 = len.parse().with_context(|| format!("bad prefix length {len:?}"))?;
    if len > 32 {
        bail!("IPv4 prefix length {len} > 32");
    }
    Ok((addr, len))
}
