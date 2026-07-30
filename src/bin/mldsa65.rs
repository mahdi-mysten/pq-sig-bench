// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-65 head-to-head: mysten-mldsa-native-rs against aws-lc-rs, keygen /
//! sign / verify. Both sides must pass their self-check and the two-way
//! cross-verification before anything is timed.
//!
//! Measurement is paired and interleaved (see `timing::measure_paired`):
//! alternating per-side batches, batch min for the fixed-work ops and batch
//! mean for rejection-sampled signing, median across rounds. A plain
//! median-of-1000-then-compare design is not robust here — the macOS
//! scheduler can park one library's entire block on an efficiency core or a
//! lower frequency step, which shifts every sample in the block uniformly
//! and leaves the median none the wiser. The per-round delta column is the
//! trustworthy number: environment drift hits both sides of a round and
//! cancels. Interleaving does make the two sides share caches and branch
//! predictor, so absolute cells can read a few percent different from a
//! solo run; the delta is the quantity this bin exists for.
//!
//! Build with `--no-default-features` to measure the wrapper's portable C
//! instead of the native backend.

use pq_sig_bench::schemes::{mldsa, mldsa_mysten};
use pq_sig_bench::timing::{self, BatchStat, Paired, RoundStats};
use pq_sig_bench::{sign_msg, Scheme, MSG};

use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};
use mysten_mldsa_native_rs as wrapper;
use rand::rngs::OsRng;
use rand::RngCore;

/// 100 × 10 = 1000 timed calls per side for the fixed-work ops.
const ROUNDS: usize = 100;
const PER_ROUND: usize = 10;
/// Signing is rejection-sampled, so its per-round batch mean needs more
/// draws to converge on the expected cost: 100 × 50 = 5000 calls per side.
const SIGN_PER_ROUND: usize = 50;
const WARMUP: usize = 20;

fn fmt_us(ns: u64) -> String {
    format!("{:.1}", ns as f64 / 1e3)
}

/// `median [p10 .. p90]` in µs; a wide interval means the run was disturbed.
fn cell(s: &RoundStats) -> String {
    format!(
        "{} µs [{} .. {}]",
        fmt_us(s.median_ns),
        fmt_us(s.p10_ns),
        fmt_us(s.p90_ns)
    )
}

fn delta_cell(d: (f64, f64, f64)) -> String {
    format!("{:+.1}% [{:+.1} .. {:+.1}]", d.1, d.0, d.2)
}

/// Keep the timing thread in the interactive QoS band. Without this the
/// scheduler is free to move it to an efficiency core mid-run; a block that
/// lands there reads 15–30% slow with nothing in-process to notice.
#[cfg(target_os = "macos")]
fn pin_to_performance_cores() {
    unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0);
    }
}
#[cfg(not(target_os = "macos"))]
fn pin_to_performance_cores() {}

fn main() {
    assert!(
        mldsa_mysten::MlDsa65Mysten.self_check(),
        "mysten wrapper self-check failed"
    );
    assert!(
        mldsa::ML_DSA_65_ROW.self_check(),
        "aws-lc-rs self-check failed"
    );
    assert!(
        mldsa_mysten::cross_check_with_aws_lc(),
        "cross-verification failed: the two rows do not implement the same scheme"
    );
    eprintln!("self-checks and two-way cross-verification ok");

    pin_to_performance_cores();
    eprintln!("ramping cpu…");
    timing::ramp_cpu(500);

    // One long-lived key pair and signature per side, mirroring each other:
    // hedged rnd drawn inside the sign closures on both sides (aws-lc does it
    // internally), counter messages so signing samples many rejection paths.
    let (m_sk, m_vk, m_sig) = mldsa_mysten::generate();
    let a_kp = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("aws-lc keygen");
    let a_pk = a_kp.public_key().as_ref().to_vec();
    let mut a_sig = vec![0u8; wrapper::SIGNATURE_LENGTH];
    a_kp.sign(MSG, &mut a_sig).expect("aws-lc sign");
    let a_upk = UnparsedPublicKey::new(&ML_DSA_65, a_pk.as_slice());

    let keygen = timing::measure_paired(
        || {
            let mut seed = [0u8; wrapper::SEED_LENGTH];
            OsRng.fill_bytes(&mut seed);
            wrapper::SigningKeySeed::from(seed).expand()
        },
        || PqdsaKeyPair::generate(&ML_DSA_65_SIGNING),
        WARMUP,
        ROUNDS,
        PER_ROUND,
        BatchStat::Min,
    );

    let mut i = 0u64;
    let mut j = 0u64;
    let mut sig_buf = vec![0u8; wrapper::SIGNATURE_LENGTH];
    let sign = timing::measure_paired(
        || {
            i += 1;
            let mut rnd = [0u8; wrapper::RND_LENGTH];
            OsRng.fill_bytes(&mut rnd);
            m_sk.sign(&sign_msg(i), b"", &rnd)
                .expect("the empty context cannot exceed the length limit")
        },
        || {
            j += 1;
            a_kp.sign(&sign_msg(j), &mut sig_buf)
        },
        WARMUP,
        ROUNDS,
        SIGN_PER_ROUND,
        BatchStat::Mean,
    );

    let verify = timing::measure_paired(
        || m_vk.verify(MSG, b"", &m_sig).is_ok(),
        || a_upk.verify(MSG, &a_sig).is_ok(),
        WARMUP,
        ROUNDS,
        PER_ROUND,
        BatchStat::Min,
    );

    let backend = mldsa_mysten::MlDsa65Mysten.meta().name;
    println!();
    println!(
        "ML-DSA-65 — {} interleaved rounds × {} calls (sign: {}), median across rounds — {} / {}",
        ROUNDS,
        PER_ROUND,
        SIGN_PER_ROUND,
        std::env::consts::ARCH,
        std::env::consts::OS,
    );
    println!(
        "pk {} B, sig {} B, sk (seed) {} B",
        wrapper::PUBLIC_KEY_LENGTH,
        wrapper::SIGNATURE_LENGTH,
        wrapper::SEED_LENGTH,
    );
    println!();
    println!(
        "  {:<8} {:<26} {:<26} Δ per round vs aws-lc",
        "op", backend, "aws-lc-rs"
    );
    // keygen/verify: min per batch (fixed work, one-sided noise);
    // sign: mean per batch (rejection sampling makes the work itself random).
    for (op, p) in [("keygen", &keygen), ("sign", &sign), ("verify", &verify)] {
        let Paired { a, b, delta_pct } = p;
        println!(
            "  {:<8} {:<26} {:<26} {}",
            op,
            cell(a),
            cell(b),
            delta_cell(*delta_pct),
        );
    }
    println!();
}
