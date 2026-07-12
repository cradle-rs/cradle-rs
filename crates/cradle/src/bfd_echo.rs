//! BFD Echo originator — the transmit half of the absorbed xdp-bfd-echo helper.
//!
//! A background task that transmits self-addressed BFD Echo frames (udp/3785)
//! for the sessions cradle's control plane arms via `ArmBfdEcho`, so the peer's
//! forwarding plane (our XDP reflector at the far end, or FRR) hairpins them back
//! inbound where `cradle_xdp`'s `reflect_v4/v6` recognizes the return (source in
//! `OUR_LOCAL_IPS`) and re-arms the per-session `bpf_timer`. Detection itself is
//! in the kernel (`ECHO_TIMERS`); this task only *sends* + covers the bootstrap
//! window (no return seen yet, `armed == 0`) with a userspace timeout that sets
//! the map's `down` flag so `watch_bfd` reports it uniformly.
//!
//! Ported from `crates/xdp-bfd-echo/src/sender.rs`; the frame layout is
//! byte-identical (the eBPF matches the `{magic, discr, seq, tx_ts}` payload).
//! Driven over an `mpsc` channel (replacing the standalone helper's stdin), so
//! `ArmBfdEcho`/`DisarmBfdEcho` become `EchoCmd::Add`/`Del`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, warn};

use crate::dataplane::Dataplane;

/// A command from the control plane to the originator task.
pub enum EchoCmd {
    /// Start (or retune) originating Echo for `discr` toward `peer` on `oif`.
    Add {
        discr: u32,
        oif: String,
        local: IpAddr,
        peer: IpAddr,
        tx: Duration,
        detect: Duration,
    },
    /// Stop originating Echo for `discr`.
    Del { discr: u32 },
}

/// One originating Echo session, keyed by our local discriminator.
struct EchoSession {
    oif: String,
    local: IpAddr,
    peer: IpAddr,
    peer_mac: Option<[u8; 6]>,
    tx: Duration,
    detect: Duration,
    next_tx: Instant,
    /// When the session was armed — the start of the bootstrap window in which
    /// the kernel timer hasn't armed yet (no return seen).
    added: Instant,
    seq: u32,
}

/// A per-interface AF_PACKET TX socket + our MAC on it + its ifindex.
struct Io {
    fd: OwnedFd,
    if_mac: [u8; 6],
    ifindex: u32,
}

/// The originator background task.
pub struct BfdEchoEngine {
    dp: Arc<Mutex<Dataplane>>,
    rx: UnboundedReceiver<EchoCmd>,
    sessions: HashMap<u32, EchoSession>,
    /// AF_PACKET sockets per egress interface, opened lazily (need CAP_NET_RAW).
    io: HashMap<String, Io>,
}

impl BfdEchoEngine {
    /// Spawn the originator task. Runs until the command channel closes (Control
    /// dropped).
    pub fn spawn(dp: Arc<Mutex<Dataplane>>, rx: UnboundedReceiver<EchoCmd>) {
        tokio::spawn(async move {
            BfdEchoEngine {
                dp,
                rx,
                sessions: HashMap::new(),
                io: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                cmd = self.rx.recv() => match cmd {
                    Some(cmd) => self.handle(cmd),
                    None => return, // control plane gone
                },
                _ = tick.tick() => self.tick().await,
            }
        }
    }

    fn handle(&mut self, cmd: EchoCmd) {
        match cmd {
            EchoCmd::Add {
                discr,
                oif,
                local,
                peer,
                tx,
                detect,
            } => {
                let now = Instant::now();
                self.sessions.insert(
                    discr,
                    EchoSession {
                        oif,
                        local,
                        peer,
                        peer_mac: None,
                        tx,
                        detect,
                        next_tx: now,
                        added: now,
                        seq: 0,
                    },
                );
                debug!("bfd echo tx: add discr={discr} {local}->{peer}");
            }
            EchoCmd::Del { discr } => {
                self.sessions.remove(&discr);
                debug!("bfd echo tx: del discr={discr}");
            }
        }
    }

    /// Every 10ms: transmit due Echoes, then bootstrap-timeout any session whose
    /// kernel timer hasn't armed within its detection window.
    async fn tick(&mut self) {
        if self.sessions.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut bootstrap_down: Vec<u32> = Vec::new();
        // Collect the sessions to service first (borrow-checker: transmit mutates
        // io + session fields, and we can't hold a session borrow across the async
        // MAC lookup).
        let discrs: Vec<u32> = self.sessions.keys().copied().collect();
        for discr in discrs {
            let (due, oif, local, peer, mut peer_mac, seq, detect, added) = {
                let s = &self.sessions[&discr];
                (
                    now >= s.next_tx,
                    s.oif.clone(),
                    s.local,
                    s.peer,
                    s.peer_mac,
                    s.seq,
                    s.detect,
                    s.added,
                )
            };
            if due {
                if peer_mac.is_none() {
                    peer_mac = lookup_mac(&oif, peer).await;
                }
                if let Some(mac) = peer_mac
                    && let Some(io) = self.io_for(&oif)
                {
                    let res = match local {
                        IpAddr::V4(l) => {
                            let f = build_echo(&io.if_mac, &mac, l, discr, seq, now_micros());
                            send_frame(io.fd.as_raw_fd(), io.ifindex, ETH_P_IP, &mac, &f)
                        }
                        IpAddr::V6(l) => {
                            let f = build_echo_v6(&io.if_mac, &mac, l, discr, seq, now_micros());
                            send_frame(io.fd.as_raw_fd(), io.ifindex, ETH_P_IPV6, &mac, &f)
                        }
                    };
                    if let Err(e) = res {
                        debug!("bfd echo tx: send discr={discr}: {e}");
                    }
                }
                if let Some(s) = self.sessions.get_mut(&discr) {
                    s.peer_mac = peer_mac;
                    s.seq = s.seq.wrapping_add(1);
                    s.next_tx = now + jitter(s.tx);
                }
            }
            if now.duration_since(added) > detect {
                bootstrap_down.push(discr);
            }
        }
        if !bootstrap_down.is_empty() {
            let mut dp = self.dp.lock().await;
            for discr in bootstrap_down {
                dp.bfd_echo_mark_down(discr);
            }
        }
    }

    /// Get (opening lazily) the AF_PACKET socket for `oif`. `None` if it can't be
    /// opened (e.g. missing CAP_NET_RAW, bad interface) — logged once per oif.
    fn io_for(&mut self, oif: &str) -> Option<&Io> {
        if !self.io.contains_key(oif) {
            match open_io(oif) {
                Ok(io) => {
                    self.io.insert(oif.to_string(), io);
                }
                Err(e) => {
                    warn!("bfd echo tx: cannot open AF_PACKET on {oif}: {e} (need CAP_NET_RAW)");
                    return None;
                }
            }
        }
        self.io.get(oif)
    }
}

fn open_io(oif: &str) -> anyhow::Result<Io> {
    let ifindex = if_nametoindex(oif)?;
    let fd = open_af_packet(ifindex)?;
    let if_mac = read_if_mac(oif)?;
    Ok(Io {
        fd,
        if_mac,
        ifindex,
    })
}

// ---- constants + frame construction (byte-identical to sender.rs) ----------

const ECHO_MAGIC: u32 = 0x7a62_6664;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const BFD_ECHO_PORT: u16 = 3785;
const ECHO_TTL: u8 = 255;
const IPPROTO_UDP: u8 = 17;

const ETH_HLEN: usize = 14;
const IP_HLEN: usize = 20;
const IP6_HLEN: usize = 40;
const UDP_HLEN: usize = 8;
/// `{ magic:u32, discr:u32, seq:u32, tx_ts_us:u64 }`, big-endian.
const PAYLOAD_LEN: usize = 4 + 4 + 4 + 8;
const FRAME_LEN: usize = ETH_HLEN + IP_HLEN + UDP_HLEN + PAYLOAD_LEN;
const FRAME6_LEN: usize = ETH_HLEN + IP6_HLEN + UDP_HLEN + PAYLOAD_LEN;

/// Build a self-addressed IPv4 BFD Echo frame (src == dst == `local`, TTL 255).
fn build_echo(
    if_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    local: Ipv4Addr,
    discr: u32,
    seq: u32,
    ts: u64,
) -> [u8; FRAME_LEN] {
    let mut f = [0u8; FRAME_LEN];
    f[0..6].copy_from_slice(dst_mac);
    f[6..12].copy_from_slice(if_mac);
    f[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
    {
        let ip = &mut f[ETH_HLEN..ETH_HLEN + IP_HLEN];
        ip[0] = 0x45; // version 4, IHL 5
        ip[1] = 0xc0; // DSCP CS6 (internetwork control), matches FRR
        let total = (IP_HLEN + UDP_HLEN + PAYLOAD_LEN) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip[8] = ECHO_TTL;
        ip[9] = IPPROTO_UDP;
        ip[12..16].copy_from_slice(&local.octets());
        ip[16..20].copy_from_slice(&local.octets());
        let ipck = checksum(ip, 0);
        ip[10..12].copy_from_slice(&ipck.to_be_bytes());
    }
    let udp_off = ETH_HLEN + IP_HLEN;
    let udp_len = (UDP_HLEN + PAYLOAD_LEN) as u16;
    f[udp_off..udp_off + 2].copy_from_slice(&BFD_ECHO_PORT.to_be_bytes());
    f[udp_off + 2..udp_off + 4].copy_from_slice(&BFD_ECHO_PORT.to_be_bytes());
    f[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    let pl = ETH_HLEN + IP_HLEN + UDP_HLEN;
    f[pl..pl + 4].copy_from_slice(&ECHO_MAGIC.to_be_bytes());
    f[pl + 4..pl + 8].copy_from_slice(&discr.to_be_bytes());
    f[pl + 8..pl + 12].copy_from_slice(&seq.to_be_bytes());
    f[pl + 12..pl + 20].copy_from_slice(&ts.to_be_bytes());
    let udpck = udp_checksum(&local, &local, &f[udp_off..]);
    f[udp_off + 6..udp_off + 8].copy_from_slice(&udpck.to_be_bytes());
    f
}

/// IPv6 analogue of [`build_echo`] (self-addressed link-local, Hop Limit 255).
fn build_echo_v6(
    if_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    local: Ipv6Addr,
    discr: u32,
    seq: u32,
    ts: u64,
) -> [u8; FRAME6_LEN] {
    let mut f = [0u8; FRAME6_LEN];
    f[0..6].copy_from_slice(dst_mac);
    f[6..12].copy_from_slice(if_mac);
    f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    {
        let ip = &mut f[ETH_HLEN..ETH_HLEN + IP6_HLEN];
        ip[0] = 0x60; // version 6
        let payload_len = (UDP_HLEN + PAYLOAD_LEN) as u16;
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = IPPROTO_UDP; // Next Header
        ip[7] = ECHO_TTL; // Hop Limit
        ip[8..24].copy_from_slice(&local.octets());
        ip[24..40].copy_from_slice(&local.octets());
    }
    let udp_off = ETH_HLEN + IP6_HLEN;
    let udp_len = (UDP_HLEN + PAYLOAD_LEN) as u16;
    f[udp_off..udp_off + 2].copy_from_slice(&BFD_ECHO_PORT.to_be_bytes());
    f[udp_off + 2..udp_off + 4].copy_from_slice(&BFD_ECHO_PORT.to_be_bytes());
    f[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    let pl = udp_off + UDP_HLEN;
    f[pl..pl + 4].copy_from_slice(&ECHO_MAGIC.to_be_bytes());
    f[pl + 4..pl + 8].copy_from_slice(&discr.to_be_bytes());
    f[pl + 8..pl + 12].copy_from_slice(&seq.to_be_bytes());
    f[pl + 12..pl + 20].copy_from_slice(&ts.to_be_bytes());
    let udpck = udp_checksum_v6(&local, &local, &f[udp_off..]);
    f[udp_off + 6..udp_off + 8].copy_from_slice(&udpck.to_be_bytes());
    f
}

/// Internet checksum over `data` plus a 32-bit `initial` accumulator.
fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum over the IPv4 pseudo-header + UDP + payload.
fn udp_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    for o in [src.octets(), dst.octets()] {
        sum += u16::from_be_bytes([o[0], o[1]]) as u32;
        sum += u16::from_be_bytes([o[2], o[3]]) as u32;
    }
    sum += IPPROTO_UDP as u32;
    sum += udp.len() as u32;
    let ck = checksum(udp, sum);
    if ck == 0 { 0xffff } else { ck }
}

/// UDP checksum over the IPv6 pseudo-header (RFC 8200 §8.1) + UDP + payload.
fn udp_checksum_v6(src: &Ipv6Addr, dst: &Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum = 0u32;
    for a in [src.octets(), dst.octets()] {
        let mut i = 0;
        while i < 16 {
            sum += u16::from_be_bytes([a[i], a[i + 1]]) as u32;
            i += 2;
        }
    }
    sum += udp.len() as u32;
    sum += IPPROTO_UDP as u32;
    let ck = checksum(udp, sum);
    if ck == 0 { 0xffff } else { ck }
}

// ---- socket / interface helpers --------------------------------------------

fn if_nametoindex(iface: &str) -> anyhow::Result<u32> {
    let cname = std::ffi::CString::new(iface)?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        anyhow::bail!(
            "if_nametoindex({iface}): {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(idx)
}

fn read_if_mac(iface: &str) -> anyhow::Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))?;
    parse_mac(s.trim())
}

fn parse_mac(s: &str) -> anyhow::Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split(':');
    for b in mac.iter_mut() {
        *b = u8::from_str_radix(
            parts.next().ok_or_else(|| anyhow::anyhow!("mac octet"))?,
            16,
        )?;
    }
    Ok(mac)
}

/// Resolve `peer` → MAC for either family on `oif` from the kernel neighbour
/// cache. `None` if unresolved yet (retried next tick); the BFD/routing adjacency
/// keeps the entry warm.
async fn lookup_mac(oif: &str, peer: IpAddr) -> Option<[u8; 6]> {
    match peer {
        IpAddr::V4(p) => arp_lookup(oif, p),
        IpAddr::V6(p) => ndp_lookup(oif, p).await,
    }
}

/// IPv4 peer → MAC from `/proc/net/arp` on `oif`.
fn arp_lookup(oif: &str, peer: Ipv4Addr) -> Option<[u8; 6]> {
    let text = std::fs::read_to_string("/proc/net/arp").ok()?;
    for line in text.lines().skip(1) {
        let mut c = line.split_whitespace();
        let ip = c.next()?;
        let _hw = c.next()?;
        let _flags = c.next()?;
        let mac = c.next()?;
        let _mask = c.next()?;
        let dev = c.next()?;
        if dev == oif && ip.parse::<Ipv4Addr>().ok() == Some(peer) && mac != "00:00:00:00:00:00" {
            return parse_mac(mac).ok();
        }
    }
    None
}

/// IPv6 (link-local) peer → MAC via `ip -6 neigh show dev <oif>` (no /proc
/// equivalent for the IPv6 neighbour table). Async to keep the subprocess off
/// the runtime's critical path.
async fn ndp_lookup(oif: &str, peer: Ipv6Addr) -> Option<[u8; 6]> {
    let out = tokio::process::Command::new("ip")
        .args(["-6", "neigh", "show", "dev", oif])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(addr) = it.next() else { continue };
        if addr.parse::<Ipv6Addr>().ok() != Some(peer) {
            continue;
        }
        while let Some(tok) = it.next() {
            if tok == "lladdr"
                && let Some(mac) = it.next()
                && mac != "00:00:00:00:00:00"
            {
                return parse_mac(mac).ok();
            }
        }
    }
    None
}

fn open_af_packet(ifindex: u32) -> anyhow::Result<OwnedFd> {
    let proto = (ETH_P_IP).to_be() as i32;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_NONBLOCK, proto) };
    if fd < 0 {
        anyhow::bail!("AF_PACKET socket: {}", std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (ETH_P_IP).to_be();
    sll.sll_ifindex = ifindex as i32;
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        anyhow::bail!(
            "bind AF_PACKET to ifindex {ifindex}: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(fd)
}

fn send_frame(
    fd: i32,
    ifindex: u32,
    ethertype: u16,
    dst_mac: &[u8; 6],
    frame: &[u8],
) -> std::io::Result<()> {
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = ethertype.to_be();
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(dst_mac);
    let n = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// 75–100% of `base` (RFC 5880 §6.8.9), clock-derived (no RNG dep) — only needs
/// to desynchronize sessions.
fn jitter(base: Duration) -> Duration {
    let pct = 75 + (now_micros() % 26); // 75..=100
    base * pct as u32 / 100
}
