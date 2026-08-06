// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Runs every row (self-check, then measure), then the ML-DSA-65 contender
//! comparison, and writes `REPORT.md` and `results.csv` in one go.
//!
//! The method preamble in REPORT.md is generated from what this run actually
//! did - pin result, clock, cycle-counter availability - so it can never
//! claim a Linux-only capability on a macOS run or vice versa.
use pq_sig_bench::{all_schemes, timing, Budget, Row, Timing};
use std::fmt::Write as _;
use std::fs;

/// Milliseconds of busy-spin CPU warmup before any measurement.
const RAMP_MS: u64 = 500;

fn fmt_ns(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.2} s", ns as f64 / 1e9)
    } else if ns >= 1_000_000 {
        format!("{:.2} ms", ns as f64 / 1e6)
    } else if ns >= 1_000 {
        format!("{:.1} µs", ns as f64 / 1e3)
    } else {
        format!("{} ns", ns)
    }
}

fn opt_ns(t: Option<Timing>) -> String {
    match t {
        Some(t) => fmt_ns(t.ns_median),
        None => "n/a".to_string(),
    }
}

/// The keygen/sign/verify iteration counts actually sampled for a row,
/// e.g. "1000/125/1000". This is the honest record behind "median over N
/// iterations, fewer for slow schemes".
fn fmt_iters(keygen: Option<Timing>, sign: Option<Timing>, verify: Timing) -> String {
    let one = |t: Option<Timing>| t.map(|t| t.iters.to_string()).unwrap_or_else(|| "-".into());
    format!("{}/{}/{}", one(keygen), one(sign), verify.iters)
}

/// CSV fragment for one op: `median,p10,p90,iters`, empty cells if unmeasured.
fn csv_op(t: Option<Timing>) -> String {
    match t {
        Some(t) => format!("{},{},{},{}", t.ns_median, t.ns_p10, t.ns_p90, t.iters),
        None => ",,,".to_string(),
    }
}

fn main() {
    let budget = Budget::default();
    let schemes = all_schemes();

    // Pin before ramping so the busy-spin heats the core we then measure on.
    let pin_desc = timing::pin_thread();
    eprintln!("thread pin: {pin_desc}");
    eprintln!("ramping cpu…");
    timing::ramp_cpu(RAMP_MS);

    eprintln!("running {} rows (self-check + measure)…", schemes.len());
    let mut rows: Vec<Row> = Vec::with_capacity(schemes.len());
    for s in &schemes {
        let m = s.meta();
        assert!(
            s.self_check(),
            "self-check FAILED for {} / {}",
            m.scheme,
            m.name
        );
        eprintln!("  • {:<18} {:<28} ok", m.scheme, m.name);
        rows.push(s.measure(&budget));
    }

    // The reference row for the implementation-options section below.
    let ours = rows
        .iter()
        .find(|r| r.meta.scheme == "ML-DSA-65")
        .expect("all_schemes() always contains the ML-DSA-65 row");
    eprintln!("running ML-DSA-65 contenders (cross-check + measure)…");
    let contenders = pq_sig_bench::schemes::mldsa_options::measure_contenders(&budget);

    // The gas-proxy anchor: what a validator runs today.
    let ed25519_verify_ns = rows
        .iter()
        .find(|r| r.meta.scheme == "Ed25519")
        .map(|r| r.verify.ns_median);
    let ratio_ed = |r: &Row| -> String {
        match ed25519_verify_ns {
            Some(a) if a > 0 => format!("{:.2}×", r.verify.ns_median as f64 / a as f64),
            _ => "-".to_string(),
        }
    };

    // Method lines built from what this run actually did.
    let cycles_line = match timing::cycle_counter_desc() {
        Some(desc) => desc.to_string(),
        None if cfg!(all(target_os = "macos", target_arch = "aarch64")) => {
            "none - Apple Silicon has no user-space cycle counter; wall clock only \
             (on x86_64 Linux this report reads rdpmc CPU_CYCLES)"
                .to_string()
        }
        None => "none on this platform; wall clock only \
                 (on x86_64 Linux this report reads rdpmc CPU_CYCLES)"
            .to_string(),
    };

    // ---- REPORT.md ----
    let mut md = String::new();
    writeln!(md, "# PQ Signature Benchmark - Measured Report\n").unwrap();
    writeln!(
        md,
        "> One implementation per row; each passes a sign→verify + tamper self-check\n\
         > before timing.\n\
         >\n\
         > **Method.** Operations are timed one at a time on a warmed, pinned thread.\n\
         > Each number is the median of **{target} iterations**; an op whose one-call\n\
         > probe exceeds {slow_ms} ms gets proportionally fewer (floor {floor}) so a\n\
         > measurement stays near {budget_s} s - the `iters` column records the actual\n\
         > keygen/sign/verify counts per row. p10/p90 for every op are in `results.csv`.\n\
         > - Wall clock: {clock}.\n\
         > - Cycle counter: {cycles}.\n\
         > - Thread pinning: {pin}.\n\
         > - Warmup: {ramp} ms CPU ramp before any measurement, then {warmup} untimed\n\
         >   iterations per op.\n\
         > - Host: {arch} {os}.\n",
        target = budget.target_iters,
        slow_ms = timing::SLOW_OP_NS / 1_000_000,
        floor = timing::MIN_ITERS,
        budget_s = timing::OP_TIME_BUDGET_NS / 1_000_000_000,
        clock = timing::clock_desc(),
        cycles = cycles_line,
        pin = pin_desc,
        ramp = RAMP_MS,
        warmup = budget.warmup,
        arch = std::env::consts::ARCH,
        os = std::env::consts::OS,
    )
    .unwrap();

    writeln!(md, "## 1. Verify cost + footprint\n").unwrap();
    writeln!(
        md,
        "| Scheme | Implementation | pk (B) | sig (B) | pk+sig (B) | keygen | sign | verify | vs Ed25519 | iters (kg/sign/vf) |"
    )
    .unwrap();
    writeln!(md, "| --- | --- | --:| --:| --:| --:| --:| --:| --:| --:|").unwrap();
    for r in &rows {
        writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            if r.meta.scheme == "ML-DSA-65" {
                "**ML-DSA-65** (our pick)".to_string()
            } else {
                r.meta.scheme.to_string()
            },
            r.meta.name,
            r.pk_len,
            r.sig_len,
            r.onchain_bytes(),
            opt_ns(r.keygen),
            opt_ns(r.sign),
            fmt_ns(r.verify.ns_median),
            ratio_ed(r),
            fmt_iters(r.keygen, r.sign, r.verify),
        )
        .unwrap();
    }

    // Each cell: the contender's median, plus how far it sits from our
    // ML-DSA-65 row for the same op - (theirs/ours − 1) as a signed percent.
    let vs_ours = |theirs: Timing, ours: Option<Timing>| -> String {
        match ours {
            Some(o) if o.ns_median > 0 => format!(
                "{} ({:+.0}%)",
                fmt_ns(theirs.ns_median),
                (theirs.ns_median as f64 / o.ns_median as f64 - 1.0) * 100.0
            ),
            _ => fmt_ns(theirs.ns_median),
        }
    };
    writeln!(md, "\n## 2. ML-DSA-65 implementation options\n").unwrap();
    writeln!(
        md,
        "Percentages are relative to the ML-DSA-65 pick ({}) in the table above.\n",
        ours.meta.name
    )
    .unwrap();
    writeln!(
        md,
        "| Implementation | keygen | sign | verify | iters (kg/sign/vf) |"
    )
    .unwrap();
    writeln!(md, "| --- | --:| --:| --:| --:|").unwrap();
    for (name, kg, sg, vf) in &contenders {
        writeln!(
            md,
            "| {} | {} | {} | {} | {} |",
            name,
            vs_ours(*kg, ours.keygen),
            vs_ours(*sg, ours.sign),
            vs_ours(*vf, Some(ours.verify)),
            fmt_iters(Some(*kg), Some(*sg), *vf),
        )
        .unwrap();
    }

    if rows.iter().any(|r| r.verify.cyc_median.is_some()) {
        writeln!(md, "\n## 2b. Verify cycles (rdpmc CPU_CYCLES, median)\n").unwrap();
        writeln!(md, "| Scheme | Implementation | verify cycles |").unwrap();
        writeln!(md, "| --- | --- | --:|").unwrap();
        for r in &rows {
            writeln!(
                md,
                "| {} | {} | {} |",
                r.meta.scheme,
                r.meta.name,
                r.verify
                    .cyc_median
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into())
            )
            .unwrap();
        }
    }

    let out = |name: &str| format!("{}/{}", env!("CARGO_MANIFEST_DIR"), name);
    fs::write(out("REPORT.md"), &md).expect("write REPORT.md");

    // ---- results.csv ----
    let mut csv = String::new();
    writeln!(
        csv,
        "scheme,impl,pk_len,sig_len,sk_len,\
         keygen_ns,keygen_p10_ns,keygen_p90_ns,keygen_iters,\
         sign_ns,sign_p10_ns,sign_p90_ns,sign_iters,\
         verify_ns,verify_p10_ns,verify_p90_ns,verify_iters,\
         verify_cyc,vs_ed25519"
    )
    .unwrap();
    for r in &rows {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{}",
            if r.meta.scheme == "ML-DSA-65" {
                "**ML-DSA-65** (our pick)".to_string()
            } else {
                r.meta.scheme.to_string()
            },
            r.meta.name,
            r.pk_len,
            r.sig_len,
            r.sk_len.map(|s| s.to_string()).unwrap_or_default(),
            csv_op(r.keygen),
            csv_op(r.sign),
            csv_op(Some(r.verify)),
            r.verify
                .cyc_median
                .map(|c| c.to_string())
                .unwrap_or_default(),
            ratio_ed(r).trim_end_matches('×'),
        )
        .unwrap();
    }
    // Contender rows from section 2: same columns, sizes and the Ed25519
    // ratio left empty (they belong to the scheme rows above).
    for (name, kg, sg, vf) in &contenders {
        writeln!(
            csv,
            "ML-DSA-65,{},,,,{},{},{},{},",
            name,
            csv_op(Some(*kg)),
            csv_op(Some(*sg)),
            csv_op(Some(*vf)),
            vf.cyc_median.map(|c| c.to_string()).unwrap_or_default(),
        )
        .unwrap();
    }
    fs::write(out("results.csv"), &csv).expect("write results.csv");

    println!("\n{md}");
}
