// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Adaptive-iteration median timer.
//!
//! The method, end to end: the benchmark thread is pinned first
//! ([`pin_thread`]), the CPU is brought to sustained frequency
//! ([`ramp_cpu`]), and each operation is then timed alone - warmup
//! iterations, a one-call probe to size the sample count, then the timed
//! loop. The reported number is the median, which is robust to the
//! scheduler/interrupt tail that makes means jump between runs; p10/p90 are
//! recorded too so the spread stays visible in the CSV.
//!
//! Wall clock: `std::time::Instant`, which is
//! `clock_gettime(CLOCK_MONOTONIC)` on Linux and the mach monotonic clock on
//! macOS - the same clock a hand-rolled libc binding would read, so no
//! separate binding is kept.
//!
//! Cycles: rdpmc CPU_CYCLES on x86_64 Linux only (see the `cycles` module).
//! Apple Silicon exposes no user-space cycle counter, so macOS rows are
//! wall-clock only, and the report says so.

use std::hint::black_box;
use std::time::Instant;

/// An op whose single-call probe exceeds this gets fewer than
/// `target_iters` iterations (see [`measure`]).
pub const SLOW_OP_NS: u64 = 1_000_000;

/// Rough wall-time cap for one measurement of a slow op: iterations =
/// budget / probe, clamped to [`MIN_ITERS`]`..=target_iters`. 1 s over a
/// 1 ms threshold makes the boundary continuous: a probe right at 1 ms
/// still yields the full 1000 iterations.
pub const OP_TIME_BUDGET_NS: u64 = 1_000_000_000;

/// Sample-count floor, so a median still means something even for
/// SLH-DSA's hundreds-of-ms signing.
pub const MIN_ITERS: usize = 30;

/// Per-run measurement policy, shared across every scheme so the comparison
/// is apples-to-apples.
#[derive(Clone, Copy)]
pub struct Budget {
    /// Untimed iterations before the probe: pays for cold caches, branch
    /// predictors, and first-call lazy setup outside the sample.
    pub warmup: usize,
    /// Sample count for ops at or under [`SLOW_OP_NS`] per call.
    pub target_iters: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            warmup: 2,
            target_iters: 1000,
        }
    }
}

/// Result of timing one operation.
#[derive(Clone, Copy)]
pub struct Timing {
    pub ns_median: u64,
    /// 10th/90th percentiles of the same sample; a wide p10–p90 band means
    /// the median above it deserves less trust.
    pub ns_p10: u64,
    pub ns_p90: u64,
    /// Median of rdpmc CPU_CYCLES deltas; `None` off x86_64 Linux or when
    /// perf is unavailable (perf_event_paranoid, missing rdpmc cap).
    pub cyc_median: Option<u64>,
    /// Iterations actually sampled, after the adaptive scale-down.
    pub iters: usize,
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

/// Pin the calling thread for the whole run; returns a description of what
/// was actually done, printed verbatim in the report's method preamble so
/// the preamble can never claim a pin the platform didn't perform.
///
/// Linux: `sched_setaffinity` to one fixed CPU - a nonzero one, because
/// CPU 0 takes most IRQ traffic on common configurations.
#[cfg(target_os = "linux")]
pub fn pin_thread() -> String {
    let cpu = if std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        > 1
    {
        1
    } else {
        0
    };
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0 {
            format!("sched_setaffinity to CPU {cpu}")
        } else {
            format!("UNPINNED - sched_setaffinity to CPU {cpu} failed")
        }
    }
}

/// macOS has no core-pinning API; the closest is raising the thread's QoS
/// class, which stops the scheduler from parking it on efficiency cores -
/// the main source of run-to-run drift on Apple Silicon.
#[cfg(target_os = "macos")]
pub fn pin_thread() -> String {
    unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0);
    }
    "QoS USER_INTERACTIVE (macOS has no core pinning; this keeps the thread on performance cores)"
        .to_string()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn pin_thread() -> String {
    "not pinned (no pinning support wired for this OS)".to_string()
}

/// What the wall clock actually is on this platform, for the report
/// preamble. `Instant` is implemented as `clock_gettime(CLOCK_MONOTONIC)` on
/// Linux and the mach monotonic clock on macOS (std's sys/time.rs), so
/// reading it is the same syscall a direct libc call would make.
pub fn clock_desc() -> &'static str {
    if cfg!(target_os = "linux") {
        "CLOCK_MONOTONIC (via std::time::Instant)"
    } else if cfg!(target_os = "macos") {
        "mach monotonic clock via std::time::Instant (macOS's CLOCK_MONOTONIC equivalent)"
    } else {
        "std::time::Instant (monotonic)"
    }
}

/// `Some(description)` when the cycle counter is live on this thread,
/// `None` otherwise. The report uses this to only claim what actually ran.
pub fn cycle_counter_desc() -> Option<&'static str> {
    cycles::desc()
}

/// Time `f`: `warmup` untimed iterations, then a one-call probe that sizes
/// the sample count, then the timed loop. Fast ops (probe ≤ [`SLOW_OP_NS`])
/// get the full `target_iters`; slow ones get [`OP_TIME_BUDGET_NS`]` /
/// probe`, floored at [`MIN_ITERS`], so one measurement costs bounded time
/// instead of stretching the run by 1000× the op time. Every result is
/// `black_box`ed so the optimizer can't delete the work.
pub fn measure<T, F: FnMut() -> T>(mut f: F, b: &Budget) -> Timing {
    assert!(
        b.target_iters >= MIN_ITERS,
        "target below the floor would make the clamp nonsensical"
    );

    for _ in 0..b.warmup {
        black_box(f());
    }

    let t0 = Instant::now();
    black_box(f());
    let probe_ns = (t0.elapsed().as_nanos() as u64).max(1);
    let iters = if probe_ns <= SLOW_OP_NS {
        b.target_iters
    } else {
        ((OP_TIME_BUDGET_NS / probe_ns) as usize).clamp(MIN_ITERS, b.target_iters)
    };

    let mut ns = Vec::with_capacity(iters);
    let mut cy: Vec<u64> = Vec::new();

    for _ in 0..iters {
        // The cycle window sits inside the wall-clock window so it never
        // includes the Instant calls.
        let t0 = Instant::now();
        let c0 = cycles::read();
        black_box(f());
        let c1 = cycles::read();
        ns.push(t0.elapsed().as_nanos() as u64);
        if let (Some(a), Some(b)) = (c0, c1) {
            cy.push(b.wrapping_sub(a));
        }
    }

    ns.sort_unstable();
    // Nearest-rank on the sorted sample; (len-1)*p/100 keeps the index in
    // range for any sample size down to 1.
    let pct = |v: &[u64], p: usize| v[(v.len() - 1) * p / 100];

    let cyc_median = if cy.is_empty() {
        None
    } else {
        cy.sort_unstable();
        Some(pct(&cy, 50))
    };

    Timing {
        ns_median: pct(&ns, 50),
        ns_p10: pct(&ns, 10),
        ns_p90: pct(&ns, 90),
        cyc_median,
        iters,
    }
}

/// Real core cycles from user space, x86_64 Linux only:
/// `perf_event_open(PERF_COUNT_HW_CPU_CYCLES, exclude_kernel)`, mmap the
/// perf page, check `cap_user_rdpmc`, then read with `rdpmc` under the
/// seqlock protocol documented in perf_event.h. Unlike rdtsc this counts
/// actual core cycles (comparable across frequency changes), and unlike a
/// `read()` on the fd it costs tens of cycles per sample instead of a
/// syscall.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cycles {
    use std::ptr;
    use std::sync::atomic::{fence, Ordering};

    // perf_event.h values used below.
    const PERF_TYPE_HARDWARE: u32 = 0;
    const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
    const PERF_ATTR_SIZE_VER0: u32 = 64;
    const FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
    const FLAG_EXCLUDE_HV: u64 = 1 << 6;

    /// First 64 bytes of `struct perf_event_attr` (PERF_ATTR_SIZE_VER0).
    /// Declaring only the prefix and passing size = 64 keeps this
    /// independent of whichever perf ABI revision the libc crate ships.
    #[repr(C)]
    #[derive(Default)]
    struct PerfEventAttr {
        type_: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_events: u32,
        bp_type: u32,
        bp_addr: u64,
    }

    /// Prefix of `struct perf_event_mmap_page` through `pmc_width`; the
    /// rdpmc protocol needs nothing past it.
    #[repr(C)]
    struct PerfEventMmapPage {
        version: u32,
        compat_version: u32,
        lock: u32,
        index: u32,
        offset: i64,
        time_enabled: u64,
        time_running: u64,
        capabilities: u64,
        pmc_width: u16,
    }

    pub struct CycleCounter {
        fd: libc::c_int,
        page: *const PerfEventMmapPage,
    }

    impl CycleCounter {
        fn open() -> Option<CycleCounter> {
            let attr = PerfEventAttr {
                type_: PERF_TYPE_HARDWARE,
                size: PERF_ATTR_SIZE_VER0,
                config: PERF_COUNT_HW_CPU_CYCLES,
                // User-space cycles only; counting the kernel would fold
                // interrupt handlers into whichever iteration they land on.
                flags: FLAG_EXCLUDE_KERNEL | FLAG_EXCLUDE_HV,
                ..Default::default()
            };

            // pid 0 / cpu -1: this thread, whichever CPU it runs on (it is
            // pinned by the time anything is measured).
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    &attr as *const PerfEventAttr,
                    0,
                    -1,
                    -1,
                    0,
                ) as libc::c_int
            };
            if fd < 0 {
                // Typically perf_event_paranoid too high; fall back to
                // wall-clock only rather than requiring root.
                return None;
            }

            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
            let page = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    page_size,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if page == libc::MAP_FAILED {
                unsafe { libc::close(fd) };
                return None;
            }
            let counter = CycleCounter {
                fd,
                page: page as *const PerfEventMmapPage,
            };

            // cap_user_rdpmc (capabilities bit 2) is the kernel confirming
            // user-space rdpmc is wired for this event; without it the
            // instruction would fault. Dropping `counter` on the way out
            // runs Drop, which unmaps and closes.
            let caps = unsafe { ptr::read_volatile(&(*counter.page).capabilities) };
            if (caps >> 2) & 1 == 0 {
                return None;
            }
            // index can be 0 until the event is scheduled in; probe once so
            // a dead counter is reported as absent, not as an empty column.
            counter.read()?;
            Some(counter)
        }

        /// One counter sample. `None` when the event isn't scheduled on this
        /// CPU right now (mmap index 0); the caller skips that iteration's
        /// cycle delta.
        pub fn read(&self) -> Option<u64> {
            unsafe {
                loop {
                    let seq = ptr::read_volatile(&(*self.page).lock);
                    fence(Ordering::Acquire);
                    let index = ptr::read_volatile(&(*self.page).index);
                    let offset = ptr::read_volatile(&(*self.page).offset);
                    let width = ptr::read_volatile(&(*self.page).pmc_width) as u32;
                    let value = if index == 0 {
                        None
                    } else {
                        // rdpmc counter numbers are index-1 by the protocol.
                        let raw = rdpmc(index - 1);
                        // The PMC is pmc_width bits wide; sign-extend so the
                        // kernel's signed base offset composes correctly.
                        let shift = 64 - width.clamp(1, 64);
                        let signed = ((raw << shift) as i64) >> shift;
                        Some(offset.wrapping_add(signed) as u64)
                    };
                    fence(Ordering::Acquire);
                    // The kernel bumps `lock` around page updates (seqlock);
                    // retry if an update raced the reads above.
                    if ptr::read_volatile(&(*self.page).lock) == seq {
                        return value;
                    }
                }
            }
        }
    }

    impl Drop for CycleCounter {
        fn drop(&mut self) {
            unsafe {
                let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
                libc::munmap(self.page as *mut libc::c_void, page_size);
                libc::close(self.fd);
            }
        }
    }

    #[inline]
    fn rdpmc(counter: u32) -> u64 {
        let lo: u32;
        let hi: u32;
        // lfence on both sides so the counter brackets the measured op, not
        // the pipeline's reordering of it (same reason the old rdtsc path
        // was serialized).
        unsafe {
            core::arch::x86_64::_mm_lfence();
            core::arch::asm!(
                "rdpmc",
                in("ecx") counter,
                out("eax") lo,
                out("edx") hi,
                options(nomem, nostack, preserves_flags)
            );
            core::arch::x86_64::_mm_lfence();
        }
        ((hi as u64) << 32) | lo as u64
    }

    thread_local! {
        // Per-thread because the perf event is opened for the calling
        // thread; the bench only ever measures from one pinned thread.
        static COUNTER: Option<CycleCounter> = CycleCounter::open();
    }

    #[inline]
    pub fn read() -> Option<u64> {
        COUNTER.with(|c| c.as_ref().and_then(|c| c.read()))
    }

    /// `Some` only when the counter actually opened on this thread.
    pub fn desc() -> Option<&'static str> {
        COUNTER.with(|c| {
            c.as_ref()
                .map(|_| "rdpmc CPU_CYCLES (perf_event_open, user-space, exclude_kernel)")
        })
    }
}

/// No user-space cycle counter here: Apple Silicon has none, and no other
/// target is wired. Wall clock only.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod cycles {
    #[inline]
    pub fn read() -> Option<u64> {
        None
    }

    pub fn desc() -> Option<&'static str> {
        None
    }
}
