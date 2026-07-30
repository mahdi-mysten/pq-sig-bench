// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fixed-iteration median timer. Median rather than mean for robustness to
//! scheduler/turbo noise, and fixed iteration counts so medians are
//! comparable run-for-run with the PQShield NIST-sig-zoo, which uses the
//! same method.

use std::hint::black_box;
use std::time::Instant;

/// Iteration counts for one run, shared across every scheme so the
/// comparison is apples-to-apples.
#[derive(Clone, Copy)]
pub struct Budget {
    pub warmup: usize,
    /// The on-chain op and the gas driver; 1000 matches the PQShield zoo.
    pub verify_iters: usize,
    /// Keygen/sign never run on-chain and SLH-DSA signs in ~0.05–1 s, so 100
    /// keeps the run short while the median stays stable (< 1% drift).
    pub offchain_iters: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            warmup: 2,
            verify_iters: 1000,
            offchain_iters: 100,
        }
    }
}

/// Result of timing one operation.
#[derive(Clone, Copy)]
pub struct Timing {
    pub ns_median: u64,
    pub cyc_median: Option<u64>,
    pub iters: usize,
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn rdtsc_serialized() -> u64 {
    // lfence-rdtsc-lfence: a serialized read so we time the op, not pipeline
    // reordering.
    unsafe {
        core::arch::x86_64::_mm_lfence();
        let t = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        t
    }
}

/// Busy-spin for `ms` milliseconds so every core the scheduler might pick is
/// at its sustained frequency before anything is timed. Without this the
/// first measured row pays the ramp-up: on an M-series host the same Falcon
/// verify reads ~50% slower as row one than as row two.
pub fn ramp_cpu(ms: u64) {
    let deadline = Instant::now() + std::time::Duration::from_millis(ms);
    let mut x = 0x9e3779b97f4a7c15u64;
    while Instant::now() < deadline {
        for _ in 0..4096 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
        black_box(x);
    }
}

/// Time `f` for exactly `iters` iterations (after `warmup` untimed ones);
/// the result is `black_box`ed so the optimizer can't delete the work.
pub fn measure<T, F: FnMut() -> T>(mut f: F, warmup: usize, iters: usize) -> Timing {
    assert!(iters > 0, "zero iterations would index an empty sample set");

    for _ in 0..warmup {
        black_box(f());
    }

    let mut ns = Vec::with_capacity(iters);
    #[cfg(target_arch = "x86_64")]
    let mut cy = Vec::with_capacity(iters);

    for _ in 0..iters {
        // Cycles are the exact column cross-checked against the PQShield zoo
        let t0 = Instant::now();
        #[cfg(target_arch = "x86_64")]
        let c0 = rdtsc_serialized();
        black_box(f());
        #[cfg(target_arch = "x86_64")]
        cy.push(rdtsc_serialized().saturating_sub(c0));
        ns.push(t0.elapsed().as_nanos() as u64);
    }

    ns.sort_unstable();
    let ns_median = ns[ns.len() / 2];

    #[cfg(target_arch = "x86_64")]
    let cyc_median = {
        cy.sort_unstable();
        Some(cy[cy.len() / 2])
    };
    #[cfg(not(target_arch = "x86_64"))]
    let cyc_median = None;

    Timing {
        ns_median,
        cyc_median,
        iters,
    }
}

/// Distribution of per-round times for one side of a paired measurement.
#[derive(Clone, Copy)]
pub struct RoundStats {
    pub p10_ns: u64,
    pub median_ns: u64,
    pub p90_ns: u64,
}

/// Result of [`measure_paired`]: per-side round distributions plus the
/// distribution of the per-round delta. The delta is the number to trust:
/// drift that hits both sides (core migration, frequency steps, background
/// load) cancels out of it, while it fully contaminates an A-block-then-
/// B-block comparison.
#[derive(Clone, Copy)]
pub struct Paired {
    pub a: RoundStats,
    pub b: RoundStats,
    /// (p10, median, p90) of per-round `(a - b) / b`, in percent. If the
    /// whole interval sits on one side of zero, the difference is real.
    pub delta_pct: (f64, f64, f64),
}

/// How one batch of calls is reduced to a single per-round time.
#[derive(Clone, Copy)]
pub enum BatchStat {
    /// For ops whose work is fixed (keygen, verify): interference is
    /// one-sided — an interrupt or a slow core only ever adds time — so the
    /// min is the cleanest estimate of the true cost under that instant's
    /// conditions.
    Min,
    /// For ops whose work is intrinsically random (ML-DSA signing rejection-
    /// samples, ~4 attempts on average): the quantity of interest is the
    /// expected cost, and the min would only find the batch's luckiest draw.
    Mean,
}

fn batch_time<T>(f: &mut impl FnMut() -> T, n: usize, stat: BatchStat) -> u64 {
    match stat {
        BatchStat::Min => {
            let mut best = u64::MAX;
            for _ in 0..n {
                let t0 = Instant::now();
                black_box(f());
                best = best.min(t0.elapsed().as_nanos() as u64);
            }
            best
        }
        BatchStat::Mean => {
            // One timer span around the whole batch: the mean needs the sum
            // anyway, and this keeps the timer out of the inner loop.
            let t0 = Instant::now();
            for _ in 0..n {
                black_box(f());
            }
            t0.elapsed().as_nanos() as u64 / n as u64
        }
    }
}

/// Interleaved A/B measurement: `rounds` rounds of (`per_round` calls of A,
/// `per_round` calls of B), alternating which side goes first so ordering
/// bias cancels too. A sequential design (all of A, then all of B) lets the
/// scheduler bias an entire block — every sample in it, uniformly — and no
/// within-block statistic can detect that. Interleaving puts the paired
/// batches within a millisecond of each other, so they almost always share
/// core placement and frequency state.
pub fn measure_paired<TA, TB>(
    mut a: impl FnMut() -> TA,
    mut b: impl FnMut() -> TB,
    warmup: usize,
    rounds: usize,
    per_round: usize,
    stat: BatchStat,
) -> Paired {
    assert!(rounds > 0 && per_round > 0);
    for _ in 0..warmup {
        black_box(a());
        black_box(b());
    }

    let mut a_ns = Vec::with_capacity(rounds);
    let mut b_ns = Vec::with_capacity(rounds);
    let mut deltas = Vec::with_capacity(rounds);
    for r in 0..rounds {
        let (ta, tb);
        if r % 2 == 0 {
            ta = batch_time(&mut a, per_round, stat);
            tb = batch_time(&mut b, per_round, stat);
        } else {
            tb = batch_time(&mut b, per_round, stat);
            ta = batch_time(&mut a, per_round, stat);
        }
        a_ns.push(ta);
        b_ns.push(tb);
        deltas.push((ta as f64 - tb as f64) / tb as f64 * 100.0);
    }

    a_ns.sort_unstable();
    b_ns.sort_unstable();
    deltas.sort_unstable_by(f64::total_cmp);

    let stats = |v: &[u64]| RoundStats {
        p10_ns: v[v.len() / 10],
        median_ns: v[v.len() / 2],
        p90_ns: v[v.len() * 9 / 10],
    };
    Paired {
        a: stats(&a_ns),
        b: stats(&b_ns),
        delta_pct: (
            deltas[deltas.len() / 10],
            deltas[deltas.len() / 2],
            deltas[deltas.len() * 9 / 10],
        ),
    }
}
