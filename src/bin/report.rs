// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Runs every row (self-check, then measure) and writes `REPORT.md` and `results.csv`
use pq_sig_bench::{all_schemes, Budget, Row};
use std::fmt::Write as _;
use std::fs;

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
        None => "n/a".to_string(),
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
        assert!(
            s.self_check(),
            "self-check FAILED for {} / {}",
            m.scheme,
            m.name
        );
        eprintln!("  • {:<12} {:<24} ok", m.scheme, m.name);
        rows.push(s.measure(&budget));
    }

    // The gas-proxy anchor: what a validator runs today.
    let ed25519_verify_ns = rows
        .iter()
        .find(|r| r.meta.scheme == "Ed25519")
        .map(|r| r.verify.ns_median);
    let ratio_ed = |r: &Row| -> String {
        match ed25519_verify_ns {
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
    writeln!(md, "# PQ Signature Benchmark — Measured Report\n").unwrap();
    writeln!(
        md,
        "> One implementation per row; each passes a sign→verify + tamper self-check\n\
         > before timing (FN-DSA-512 also cross-verifies with PQClean C, both ways).\n\
         > Median of **{} iterations** for verify (the PQShield-zoo method) and\n\
         > **{}** for keygen/sign (off-chain context), warmup {}.\n\
         > Measurement host: **{}**.\n",
        budget.verify_iters, budget.offchain_iters, budget.warmup, arch
    )
    .unwrap();

    writeln!(md, "## 1. Verify cost + footprint\n").unwrap();
    writeln!(
        md,
        "| Scheme | Implementation | pk (B) | sig (B) | pk+sig (B) | keygen | sign | verify | vs Ed25519 |"
    )
    .unwrap();
    writeln!(md, "| --- | --- | --:| --:| --:| --:| --:| --:| --:|").unwrap();
    for r in &rows {
        writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            r.meta.scheme,
            r.meta.name,
            r.pk_len,
            r.sig_len,
            r.onchain_bytes(),
            opt_ns(r.keygen),
            opt_ns(r.sign),
            fmt_ns(r.verify.ns_median),
            ratio_ed(r),
        )
        .unwrap();
    }

    if has_cycles {
        writeln!(md, "\n## 2b. Verify cycles (x86_64 rdtsc, median)\n").unwrap();
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
        "scheme,impl,pk_len,sig_len,sk_len,keygen_ns,sign_ns,verify_ns,verify_cyc,verify_iters,vs_ed25519"
    )
    .unwrap();
    for r in &rows {
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{}",
            r.meta.scheme,
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
            ratio_ed(r).trim_end_matches('×'),
        )
        .unwrap();
    }
    fs::write(out("results.csv"), &csv).expect("write results.csv");

    println!("\n{md}");
}
