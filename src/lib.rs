// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Measurement harness for the post-quantum signature schemes proposed for fastcrypto
pub mod timing;
pub use timing::{Budget, Timing};

mod schemes;
pub use schemes::all_schemes;

pub const MSG: &[u8] = b"sui post-quantum native authenticator benchmark";

/// Message for sign-timing iteration `i`: [`MSG`] plus a counter, so
/// deterministic signers sample ~`iters` different rejection paths instead of
/// re-running the one path their (key, message) pair happens to hit.
pub fn sign_msg(i: u64) -> Vec<u8> {
    let mut m = MSG.to_vec();
    m.extend_from_slice(&i.to_le_bytes());
    m
}

/// Static description of a measured row.
#[derive(Clone, Copy)]
pub struct Meta {
    /// Scheme family the row belongs to ("FN-DSA-512", "ML-DSA-65").
    pub scheme: &'static str,
    /// Implementation label ("fastcrypto", "PQClean C", "aws-lc-rs").
    pub name: &'static str,
}

/// One fully-measured row.
pub struct Row {
    pub meta: Meta,
    pub pk_len: usize,
    pub sig_len: usize,
    pub sk_len: Option<usize>,
    pub keygen: Option<Timing>,
    pub sign: Option<Timing>,
    pub verify: Timing,
}

impl Row {
    /// On-chain footprint = what's stored (pk) + what's sent per tx (sig).
    pub fn onchain_bytes(&self) -> usize {
        self.pk_len + self.sig_len
    }
}

/// The measurement + correctness contract every row implements.
pub trait Scheme {
    fn meta(&self) -> Meta;
    /// Sizes + keygen/sign/verify timings under one shared budget.
    fn measure(&self, b: &Budget) -> Row;
    /// Sign→verify roundtrip must pass, a tampered one must fail. Gates
    /// every row before its timing is trusted.
    fn self_check(&self) -> bool;
}
