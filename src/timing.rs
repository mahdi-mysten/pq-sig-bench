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
