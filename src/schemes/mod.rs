// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Scheme;

mod falcon;

pub fn all_schemes() -> Vec<Box<dyn Scheme>> {
    vec![
        Box::new(falcon::Falcon512),
        Box::new(falcon::Falcon512PqClean),
    ]
}
