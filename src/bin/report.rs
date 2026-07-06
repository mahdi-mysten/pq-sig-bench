// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Runs every row (self-check, then measure) and writes `REPORT.md` and `results.csv`

use pq_sig_bench::{all_schemes, Budget, Row};
use std::fmt::Write as _;
use std::fs;

/// The reference row every verify time is compared against.
const ANCHOR: &str = "Falcon-512 (PQClean C)";

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

fn opt_ns(t: Option<pq_sig_bench::Timing>) -> String {
    match t {
        Some(t) => fmt_ns(t.ns_median),
        None => "—".to_string(),
    }
}

fn main() {
    let budget = Budget::default();
    let schemes = all_schemes();

    eprintln!("ramping cpu…");
    pq_sig_bench::timing::ramp_cpu(500);

    eprintln!("running {} rows (self-check + measure)…", schemes.len());
    let mut rows: Vec<Row> = Vec::with_capacity(schemes.len());
    for s in &schemes {
        let m = s.meta();
        assert!(s.self_check(), "self-check FAILED for {}", m.name);
        eprintln!("  • {:<28} ok", m.name);
        rows.push(s.measure(&budget));
    }

    let anchor_verify_ns = rows
        .iter()
        .find(|r| r.meta.name == ANCHOR)
        .map(|r| r.verify.ns_median);

    let ratio = |r: &Row| -> String {
        match anchor_verify_ns {
            Some(a) if a > 0 => format!("{:.2}×", r.verify.ns_median as f64 / a as f64),
            _ => "—".to_string(),
        }
    };

    let has_cycles = rows.iter().any(|r| r.verify.cyc_median.is_some());
    let arch = if has_cycles {
        "x86_64 (rdtsc cycles + ns)"
    } else {
        "non-x86 (wall-clock ns; no rdtsc)"
    };

    // ---- REPORT.md ----
    let mut md = String::new();
    writeln!(md, "# Falcon-512 Verify Benchmark — Measured Report\n").unwrap();
    writeln!(
        md,
        "> Median of **{} iterations** for verify (the PQShield-zoo method) and\n\
         > **{}** for keygen/sign (off-chain context), warmup {}.\n\
         > Measurement host: **{}**.\n",
        budget.verify_iters, budget.offchain_iters, budget.warmup, arch
    )
    .unwrap();

    writeln!(md, "## 1. Verify cost + footprint\n").unwrap();
    writeln!(
        md,
        "| Implementation | pk (B) | sig (B) | pk+sig (B) | verify | vs PQClean C |"
    )
    .unwrap();
    writeln!(md, "| --- | --:| --:| --:| --:| --:|").unwrap();
    for r in &rows {
        writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} |",
            r.meta.name,
            r.pk_len,
            r.sig_len,
            r.onchain_bytes(),
            fmt_ns(r.verify.ns_median),
            ratio(r),
        )
        .unwrap();
    }

    writeln!(md, "\n## 2. Full timing (keygen / sign / verify median)\n").unwrap();
    writeln!(
        md,
        "| Implementation | keygen | sign | verify | verify iters |"
    )
    .unwrap();
    writeln!(md, "| --- | --:| --:| --:| --:|").unwrap();
    for r in &rows {
        writeln!(
            md,
            "| {} | {} | {} | {} | {} |",
            r.meta.name,
            opt_ns(r.keygen),
            opt_ns(r.sign),
            fmt_ns(r.verify.ns_median),
            r.verify.iters,
        )
        .unwrap();
    }

    if has_cycles {
        writeln!(md, "\n## 2b. Verify cycles (x86_64 rdtsc, median)\n").unwrap();
        writeln!(md, "| Implementation | verify cycles |").unwrap();
        writeln!(md, "| --- | --:|").unwrap();
        for r in &rows {
            writeln!(
                md,
                "| {} | {} |",
                r.meta.name,
                r.verify
                    .cyc_median
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "—".into())
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
        "name,pk_len,sig_len,sk_len,keygen_ns,sign_ns,verify_ns,verify_cyc,verify_iters,vs_pqclean"
    )
    .unwrap();
    for r in &rows {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{}",
            r.meta.name,
            r.pk_len,
            r.sig_len,
            r.sk_len.map(|s| s.to_string()).unwrap_or_default(),
            r.keygen
                .map(|t| t.ns_median.to_string())
                .unwrap_or_default(),
            r.sign.map(|t| t.ns_median.to_string()).unwrap_or_default(),
            r.verify.ns_median,
            r.verify
                .cyc_median
                .map(|c| c.to_string())
                .unwrap_or_default(),
            r.verify.iters,
            ratio(r).trim_end_matches('×'),
        )
        .unwrap();
    }
    fs::write(out("results.csv"), &csv).expect("write results.csv");

    println!("\n{md}");
    eprintln!("wrote REPORT.md and results.csv");
}
