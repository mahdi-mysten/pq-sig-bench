// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Scheme;

mod ed25519;
mod falcon;
mod mldsa;

pub fn all_schemes() -> Vec<Box<dyn Scheme>> {
    vec![
        Box::new(ed25519::Ed25519Baseline),
        Box::new(falcon::Falcon512),
        Box::new(falcon::Falcon512PqClean),
        Box::new(mldsa::MlDsa44Libcrux),
        Box::new(mldsa::MlDsa44RustCrypto),
        Box::new(mldsa::MlDsa44Fips204),
        Box::new(mldsa::MlDsa44PqClean),
        Box::new(mldsa::MlDsa44AwsLc),
    ]
}
