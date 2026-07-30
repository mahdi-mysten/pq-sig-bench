// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Scheme;

mod ed25519;
mod falcon;
// pub: the `mldsa65` bin runs the aws-lc-rs row and the mysten wrapper row
// head-to-head, outside the one-implementation-per-scheme report.
pub mod mldsa;
pub mod mldsa_mysten;

pub fn all_schemes() -> Vec<Box<dyn Scheme>> {
    vec![
        Box::new(ed25519::Ed25519Baseline),
        Box::new(falcon::Falcon512Fastcrypto),
        Box::new(falcon::Falcon1024PqClean),
        Box::new(mldsa::ML_DSA_44_ROW),
        Box::new(mldsa::ML_DSA_65_ROW),
        Box::new(mldsa::ML_DSA_87_ROW),
    ]
}
