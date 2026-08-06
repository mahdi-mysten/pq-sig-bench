// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Scheme;

mod ed25519;
mod falcon;
// pub: `mldsa_options` cross-checks its contenders against the mysten wrapper
// row, outside the one-implementation-per-scheme list below.
pub mod mldsa_mysten;
pub mod mldsa_options;
mod slhdsa;

pub fn all_schemes() -> Vec<Box<dyn Scheme>> {
    vec![
        Box::new(ed25519::Ed25519Baseline),
        Box::new(falcon::Falcon512PqClean),
        Box::new(falcon::Falcon1024PqClean),
        // The hash-based alternative sits above the lattice rows: no lattice
        // assumption, priced by its signature size and signing time.
        Box::new(slhdsa::SlhDsa128sFastcrypto),
        Box::new(mldsa_mysten::MlDsa44Mysten),
        Box::new(mldsa_mysten::MlDsa65Mysten),
        Box::new(mldsa_mysten::MlDsa87Mysten),
    ]
}
