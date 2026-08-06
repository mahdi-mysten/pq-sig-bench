// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! FN-DSA (Falcon), one row per parameter set, both from PQClean's portable
//! C (`falcon-padded-512` / `falcon-padded-1024`) in the padded fixed-size
//! signature format, built without SIMD to match how fastcrypto ships C.
//!
//! Earlier revisions measured FN-DSA-512 through fastcrypto's falcon512
//! module (strict canonical verifier, sign-time re-verification gate) from
//! the `mahdi/fn-dsa-512` branch. The fastcrypto dependency now tracks the
//! sphincs branch for the SLH-DSA row, and that branch carries no falcon
//! module, so both parameter sets are measured on the same PQClean C. These
//! are raw-C numbers: FN-DSA-512 sign no longer includes fastcrypto's
//! strict-verify gate, so it reads faster than the old fastcrypto row did.

use crate::{sign_msg, timing, Budget, Meta, Row, Scheme, MSG};
use pqcrypto_falcon::{falconpadded1024 as f1024, falconpadded512 as f512};

// Both rows are the same PQClean API at different parameter sets, so one
// macro keeps them from drifting apart.
macro_rules! falcon_pqclean_row {
    ($struct:ident, $scheme:literal, $api:ident) => {
        pub struct $struct;

        impl Scheme for $struct {
            fn meta(&self) -> Meta {
                Meta {
                    scheme: $scheme,
                    name: "PQClean C",
                }
            }

            fn measure(&self, b: &Budget) -> Row {
                let (pk, sk) = $api::keypair();
                let sig = $api::detached_sign(MSG, &sk);

                let keygen = timing::measure($api::keypair, b);
                let mut i = 0u64;
                let sign = timing::measure(
                    || {
                        i += 1;
                        $api::detached_sign(&sign_msg(i), &sk)
                    },
                    b,
                );
                let verify = timing::measure(
                    || $api::verify_detached_signature(&sig, MSG, &pk).is_ok(),
                    b,
                );

                Row {
                    meta: self.meta(),
                    pk_len: $api::public_key_bytes(),
                    sig_len: $api::signature_bytes(),
                    sk_len: Some($api::secret_key_bytes()),
                    keygen: Some(keygen),
                    sign: Some(sign),
                    verify,
                }
            }

            fn self_check(&self) -> bool {
                let (pk, sk) = $api::keypair();
                let sig = $api::detached_sign(MSG, &sk);
                $api::verify_detached_signature(&sig, MSG, &pk).is_ok()
                    && $api::verify_detached_signature(&sig, b"tampered", &pk).is_err()
            }
        }
    };
}

falcon_pqclean_row!(Falcon512PqClean, "FN-DSA-512", f512);
falcon_pqclean_row!(Falcon1024PqClean, "FN-DSA-1024", f1024);
