//! DIR-24-8 expansion engine — the userspace half of the large-FIB design
//! (`docs/design/large-fib.md`).
//!
//! Pure logic: the engine owns the **shadow** route set (what *should* be
//! programmed) and turns each route add/del into a plan of packed-word slot
//! writes (`SlotWrite`) that the caller applies to the `TBL24`/`TBL8`/
//! `DEFAULT4` maps. Keeping it side-effect free is what lets the property
//! tests prove it against a reference LPM without any eBPF.
//!
//! Invariants the plan order preserves for lock-free readers:
//! * a **new** `TBL8` group is fully written *before* the `TBL24` word flips
//!   to point at it (fill-then-flip);
//! * a collapsing block's `TBL24` word flips to a direct entry *before* its
//!   group is recycled — and recycling is **lazy** (quarantine), so a reader
//!   that loaded the old `TBL24` word never indexes a group being rewritten
//!   for a different /24.

use std::collections::{HashMap, VecDeque};

use anyhow::{bail, Result};
use cradle_common::{fibw_entry, fibw_group, FibEntry, FibWord};

/// One map write in a plan. `Tbl8` indices are absolute slot indices
/// (`group * 256 + low_byte`).
#[derive(Debug, Clone, Copy)]
pub enum SlotWrite {
    Tbl24 { idx: u32, word: FibWord },
    Tbl8 { idx: u32, word: FibWord },
    Default(FibWord),
}

/// Freed groups sit in quarantine this deep before becoming allocatable
/// again (the "grace period" between a `TBL24` flip-away and slot reuse).
const QUARANTINE_DEPTH: usize = 64;

pub struct Dir24Engine {
    /// The shadow: `(network, prefix_len) → entry`. Authoritative for what
    /// should be programmed; `/0` lives here too but maps to `DEFAULT4`.
    shadow: HashMap<(u32, u8), FibEntry>,
    /// Per-/24-block count of routes with `len > 24` (the group condition).
    long_count: HashMap<u32, u32>,
    /// `/24 block → allocated TBL8 group index`.
    groups: HashMap<u32, u32>,
    /// Allocatable group indices.
    free: Vec<u32>,
    /// Recently freed groups, not yet allocatable (lazy recycle).
    quarantine: VecDeque<u32>,
}

/// Network mask for a prefix length (0 ⇒ 0).
#[inline]
const fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    }
}

impl Dir24Engine {
    /// `n_groups` is the `TBL8` pool size the maps were created with.
    pub fn new(n_groups: u32) -> Self {
        Self {
            shadow: HashMap::new(),
            long_count: HashMap::new(),
            groups: HashMap::new(),
            free: (0..n_groups).rev().collect(),
            quarantine: VecDeque::new(),
        }
    }

    /// Install/replace a route. Returns the slot writes to apply, in order.
    pub fn route_add(&mut self, addr: u32, len: u8, entry: FibEntry) -> Result<Vec<SlotWrite>> {
        if len > 32 {
            bail!("bad prefix length {len}");
        }
        let addr = addr & mask(len);
        if len == 0 {
            // The default route is never expanded (large-fib.md): one word.
            self.shadow.insert((addr, len), entry);
            return Ok(vec![SlotWrite::Default(fibw_entry(entry.nexthop_id, entry.flags))]);
        }

        // Only a len>24 add can require a new group — exactly one — so
        // validate capacity *before* mutating the shadow (no rollback).
        let blk = addr >> 8;
        if len > 24
            && !self.groups.contains_key(&blk)
            && self.free.is_empty()
            && self.quarantine.is_empty()
        {
            bail!(
                "TBL8 group pool exhausted ({} groups in use)",
                self.groups.len()
            );
        }

        let prev = self.shadow.insert((addr, len), entry);
        if len > 24 && prev.is_none() {
            *self.long_count.entry(blk).or_insert(0) += 1;
        }

        let mut out = Vec::new();
        for blk in Self::affected_blocks(addr, len) {
            self.sync_block(blk, &mut out)?;
        }
        Ok(out)
    }

    /// Remove a route (idempotent). Returns the slot writes to apply.
    pub fn route_del(&mut self, addr: u32, len: u8) -> Result<Vec<SlotWrite>> {
        if len > 32 {
            bail!("bad prefix length {len}");
        }
        let addr = addr & mask(len);
        if self.shadow.remove(&(addr, len)).is_none() {
            return Ok(Vec::new());
        }
        if len == 0 {
            return Ok(vec![SlotWrite::Default(0)]);
        }
        if len > 24 {
            let blk = addr >> 8;
            if let Some(c) = self.long_count.get_mut(&blk) {
                *c -= 1;
                if *c == 0 {
                    self.long_count.remove(&blk);
                }
            }
        }

        let mut out = Vec::new();
        for blk in Self::affected_blocks(addr, len) {
            self.sync_block(blk, &mut out)?;
        }
        Ok(out)
    }

    /// Reference longest-prefix-match over the shadow (includes `/0`).
    /// Also the oracle the property tests compare the tables against.
    pub fn lookup(&self, addr: u32) -> Option<FibEntry> {
        for len in (0..=32u8).rev() {
            if let Some(e) = self.shadow.get(&(addr & mask(len), len)) {
                return Some(*e);
            }
        }
        None
    }

    /// Number of groups currently backing blocks.
    pub fn groups_in_use(&self) -> usize {
        self.groups.len()
    }

    /// The /24 blocks a prefix covers (a route with `len ≤ 24` covers whole
    /// blocks by alignment; a longer route lives inside exactly one).
    fn affected_blocks(addr: u32, len: u8) -> std::ops::Range<u32> {
        let first = addr >> 8;
        if len > 24 {
            first..first + 1
        } else {
            first..first + (1u32 << (24 - len))
        }
    }

    /// Recompute one /24 block's forwarding state from the shadow and emit
    /// the writes that bring the tables to it.
    fn sync_block(&mut self, blk: u32, out: &mut Vec<SlotWrite>) -> Result<()> {
        let has_long = self.long_count.get(&blk).copied().unwrap_or(0) > 0;
        if has_long {
            match self.groups.get(&blk).copied() {
                Some(g) => {
                    // Live group: rewrite slots in place — each word changes
                    // directly from old cover to new cover, per-word atomic.
                    for low in 0..256u32 {
                        out.push(SlotWrite::Tbl8 {
                            idx: g * 256 + low,
                            word: self.slot_word(blk, low),
                        });
                    }
                }
                None => {
                    let g = self.alloc_group()?;
                    self.groups.insert(blk, g);
                    // Fill the whole group first…
                    for low in 0..256u32 {
                        out.push(SlotWrite::Tbl8 {
                            idx: g * 256 + low,
                            word: self.slot_word(blk, low),
                        });
                    }
                    // …then flip the block to it.
                    out.push(SlotWrite::Tbl24 {
                        idx: blk,
                        word: fibw_group(g),
                    });
                }
            }
        } else {
            // No long routes: a single direct word (or invalid). Emit the
            // flip first, then quarantine any group the block held.
            out.push(SlotWrite::Tbl24 {
                idx: blk,
                word: self.block_cover_word(blk),
            });
            if let Some(g) = self.groups.remove(&blk) {
                self.quarantine.push_back(g);
                while self.quarantine.len() > QUARANTINE_DEPTH {
                    let g = self.quarantine.pop_front().unwrap();
                    self.free.push(g);
                }
            }
        }
        Ok(())
    }

    /// Most specific route covering one host address (`len 32 → 1`; `/0` is
    /// handled at lookup time by `DEFAULT4`, never written into slots).
    fn slot_word(&self, blk: u32, low: u32) -> FibWord {
        let addr = blk << 8 | low;
        for len in (1..=32u8).rev() {
            if let Some(e) = self.shadow.get(&(addr & mask(len), len)) {
                return fibw_entry(e.nexthop_id, e.flags);
            }
        }
        0
    }

    /// Most specific `len ≤ 24` route covering a whole block (uniform across
    /// the block by alignment when no longer route exists in it).
    fn block_cover_word(&self, blk: u32) -> FibWord {
        let addr = blk << 8;
        for len in (1..=24u8).rev() {
            if let Some(e) = self.shadow.get(&(addr & mask(len), len)) {
                return fibw_entry(e.nexthop_id, e.flags);
            }
        }
        0
    }

    fn alloc_group(&mut self) -> Result<u32> {
        if let Some(g) = self.free.pop() {
            return Ok(g);
        }
        // Under exhaustion pressure, sacrifice the grace period rather than
        // fail: reuse the oldest quarantined group.
        if let Some(g) = self.quarantine.pop_front() {
            return Ok(g);
        }
        bail!(
            "TBL8 group pool exhausted ({} groups in use)",
            self.groups.len()
        );
    }
}

// =============================== tests =====================================

#[cfg(test)]
mod tests {
    use super::*;
    use cradle_common::{fibw_unpack, FIBW_ID_MASK, FIBW_TBL8, FIBW_VALID, FIB_F_ECMP, FIB_F_LOCAL};

    /// Simulated data-plane tables — mirrors `fib4_lookup` in cradle-ebpf.
    struct Sim {
        tbl24: Vec<FibWord>,
        tbl8: Vec<FibWord>,
        default4: FibWord,
    }

    impl Sim {
        fn new(n_groups: u32) -> Self {
            Self {
                tbl24: vec![0; 1 << 24],
                tbl8: vec![0; (n_groups * 256) as usize],
                default4: 0,
            }
        }

        fn apply(&mut self, writes: &[SlotWrite]) {
            for w in writes {
                match *w {
                    SlotWrite::Tbl24 { idx, word } => self.tbl24[idx as usize] = word,
                    SlotWrite::Tbl8 { idx, word } => self.tbl8[idx as usize] = word,
                    SlotWrite::Default(word) => self.default4 = word,
                }
            }
        }

        /// The datapath lookup, faithfully.
        fn lookup(&self, addr: u32) -> Option<(u32, u32)> {
            let mut w = self.tbl24[(addr >> 8) as usize];
            if w & FIBW_TBL8 != 0 {
                let group = w & FIBW_ID_MASK;
                w = self.tbl8[(group * 256 + (addr & 0xff)) as usize];
            }
            if w & FIBW_VALID == 0 {
                w = self.default4;
                if w & FIBW_VALID == 0 {
                    return None;
                }
            }
            Some(fibw_unpack(w))
        }
    }

    fn e(nexthop_id: u32, flags: u32) -> FibEntry {
        FibEntry { nexthop_id, flags }
    }

    /// Expected data-plane view of the reference LPM result.
    fn expect(eng: &Dir24Engine, addr: u32) -> Option<(u32, u32)> {
        eng.lookup(addr).map(|f| (f.nexthop_id, f.flags & 0xf))
    }

    fn check(eng: &Dir24Engine, sim: &Sim, addrs: &[u32], ctx: &str) {
        for &a in addrs {
            assert_eq!(sim.lookup(a), expect(eng, a), "{ctx}: addr {a:#010x}");
        }
    }

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    #[test]
    fn overlaps_both_orders() {
        for reversed in [false, true] {
            let mut eng = Dir24Engine::new(16);
            let mut sim = Sim::new(16);
            // /16 covering, /24 inside, /30 inside that.
            let mut routes: Vec<(u32, u8, FibEntry)> = vec![
                (0x0a010000, 16, e(1, 0)),
                (0x0a010200, 24, e(2, 0)),
                (0x0a010204, 30, e(3, FIB_F_ECMP)),
            ];
            if reversed {
                routes.reverse();
            }
            for (a, l, ent) in routes {
                sim.apply(&eng.route_add(a, l, ent).unwrap());
            }
            let samples = [
                0x0a010000, 0x0a010203, 0x0a010204, 0x0a010207, 0x0a010208, 0x0a01ffff,
                0x0a020000, // outside the /16
            ];
            check(&eng, &sim, &samples, &format!("reversed={reversed}"));
        }
    }

    #[test]
    fn delete_cover_under_group_and_collapse() {
        let mut eng = Dir24Engine::new(16);
        let mut sim = Sim::new(16);
        sim.apply(&eng.route_add(0x0a010000, 16, e(1, 0)).unwrap());
        sim.apply(&eng.route_add(0x0a010280, 26, e(2, 0)).unwrap());
        assert_eq!(eng.groups_in_use(), 1);
        let samples = [0x0a010200, 0x0a010280, 0x0a0102bf, 0x0a0102c0, 0x0a01ff01];
        check(&eng, &sim, &samples, "group over cover");

        // Delete the /16 cover: group background slots recompute to invalid.
        sim.apply(&eng.route_del(0x0a010000, 16).unwrap());
        check(&eng, &sim, &samples, "cover deleted");
        assert_eq!(sim.lookup(0x0a010200), None);
        assert_eq!(sim.lookup(0x0a010280), Some((2, 0)));

        // Delete the /26: block collapses, group quarantined.
        sim.apply(&eng.route_del(0x0a010280, 26).unwrap());
        assert_eq!(eng.groups_in_use(), 0);
        check(&eng, &sim, &samples, "collapsed");
    }

    #[test]
    fn replace_and_normalization() {
        let mut eng = Dir24Engine::new(16);
        let mut sim = Sim::new(16);
        sim.apply(&eng.route_add(0x0a020000, 24, e(1, 0)).unwrap());
        // Replace with a different nexthop; host bits set (normalized away).
        sim.apply(&eng.route_add(0x0a0200ff, 24, e(7, FIB_F_LOCAL)).unwrap());
        assert_eq!(sim.lookup(0x0a020042), Some((7, FIB_F_LOCAL)));
        // Long-route replace must not double-count the block.
        sim.apply(&eng.route_add(0x0a020010, 32, e(8, 0)).unwrap());
        sim.apply(&eng.route_add(0x0a020010, 32, e(9, 0)).unwrap());
        assert_eq!(sim.lookup(0x0a020010), Some((9, 0)));
        sim.apply(&eng.route_del(0x0a020010, 32).unwrap());
        assert_eq!(eng.groups_in_use(), 0, "replace double-counted long_count");
        assert_eq!(sim.lookup(0x0a020010), Some((7, FIB_F_LOCAL)));
    }

    #[test]
    fn default_route() {
        let mut eng = Dir24Engine::new(16);
        let mut sim = Sim::new(16);
        assert_eq!(sim.lookup(0x08080808), None);
        sim.apply(&eng.route_add(0, 0, e(42, 0)).unwrap());
        assert_eq!(sim.lookup(0x08080808), Some((42, 0)));
        sim.apply(&eng.route_add(0x08080000, 16, e(1, 0)).unwrap());
        assert_eq!(sim.lookup(0x08080808), Some((1, 0)));
        assert_eq!(sim.lookup(0x01010101), Some((42, 0)));
        sim.apply(&eng.route_del(0, 0).unwrap());
        assert_eq!(sim.lookup(0x01010101), None);
        assert_eq!(sim.lookup(0x08080808), Some((1, 0)));
    }

    #[test]
    fn group_pool_exhaustion_is_clean() {
        let mut eng = Dir24Engine::new(1);
        let mut sim = Sim::new(1);
        sim.apply(&eng.route_add(0x0a000010, 32, e(1, 0)).unwrap());
        // Second block needs a second group: must fail without touching state.
        assert!(eng.route_add(0x0a000110, 32, e(2, 0)).is_err());
        assert!(eng.lookup(0x0a000110).is_none(), "failed add leaked into shadow");
        assert_eq!(sim.lookup(0x0a000010), Some((1, 0)));
        // Same block is fine (group already allocated).
        sim.apply(&eng.route_add(0x0a000020, 32, e(3, 0)).unwrap());
        assert_eq!(sim.lookup(0x0a000020), Some((3, 0)));
    }

    /// The main correctness argument: random add/del sequences, and after
    /// every operation the simulated tables must resolve identically to the
    /// reference LPM over the shadow — for edge addresses of every live
    /// route plus random probes.
    #[test]
    fn property_random_ops_match_reference_lpm() {
        for seed in [1u64, 7, 42, 20260702] {
            let mut rng = seed;
            let n_groups = 32; // small pool: exercises quarantine + reuse
            let mut eng = Dir24Engine::new(n_groups);
            let mut sim = Sim::new(n_groups);
            let mut live: Vec<(u32, u8)> = Vec::new();
            let lens = [8u8, 12, 16, 20, 22, 24, 25, 26, 28, 30, 32];

            for step in 0..400 {
                let r = splitmix64(&mut rng);
                let del = !live.is_empty() && r % 10 < 3;
                if del {
                    let (a, l) = live.swap_remove((r >> 8) as usize % live.len());
                    sim.apply(&eng.route_del(a, l).unwrap());
                } else {
                    let len = lens[(r >> 4) as usize % lens.len()];
                    // Cluster prefixes into 10.0.0.0/9 so overlaps are common.
                    let addr = (0x0a000000 | (r >> 16) as u32 & 0x007f_ffff) & mask(len);
                    let entry = e((r >> 40) as u32 & 0xffff, (r as u32 >> 1) & 0xf);
                    match eng.route_add(addr, len, entry) {
                        Ok(w) => {
                            sim.apply(&w);
                            if !live.contains(&(addr, len)) {
                                live.push((addr, len));
                            }
                        }
                        Err(_) => continue, // pool exhausted: state must be intact
                    }
                }

                // Probe edges of every live route + a handful of randoms.
                let mut probes = Vec::with_capacity(live.len() * 4 + 8);
                for &(a, l) in &live {
                    let last = a | !mask(l);
                    probes.extend_from_slice(&[
                        a,
                        last,
                        a.wrapping_sub(1),
                        last.wrapping_add(1),
                    ]);
                }
                for _ in 0..8 {
                    probes.push(0x0a000000 | (splitmix64(&mut rng) as u32 & 0x00ff_ffff));
                }
                check(&eng, &sim, &probes, &format!("seed {seed} step {step}"));
            }
        }
    }
}
