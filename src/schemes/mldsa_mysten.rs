// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA measured through our mysten-mldsa-native-rs wrapper: the same
//! mldsa-native C that aws-lc imported, but consumed directly. The aws-lc-rs
//! contender in `mldsa_options` runs the same math, so that comparison
//! isolates what the binding and build shape cost: aws-lc goes through its
//! libcrypto build and EVP layer, the wrapper through a single-TU build and
//! direct FFI.

use crate::{sign_msg, timing, Budget, Meta, Row, Scheme, MSG};
use mysten_mldsa_native_rs as mldsa;
use rand::rngs::OsRng;
use rand::RngCore;

/// Resolved at compile time from the crate feature, so the label cannot
/// drift from what was actually measured.
const BACKEND: &str = if cfg!(feature = "mysten-native") {
    "mysten wrapper (native)"
} else {
    "mysten wrapper (portable C)"
};

pub struct MlDsa65Mysten;

/// Fresh key pair plus one signature over [`MSG`]. Pub so `mldsa_options` can
/// build its cross-verification material on the same setup.
pub fn generate() -> (mldsa::SigningKey, mldsa::VerifyingKey, mldsa::Signature) {
    let mut seed = [0u8; mldsa::SEED_LENGTH];
    OsRng.fill_bytes(&mut seed);
    let (sk, vk) = mldsa::SigningKeySeed::from(seed).expand();
    let mut rnd = [0u8; mldsa::RND_LENGTH];
    OsRng.fill_bytes(&mut rnd);
    let sig = sk
        .sign(MSG, b"", &rnd)
        .expect("the empty context cannot exceed the length limit");
    (sk, vk, sig)
}

impl Scheme for MlDsa65Mysten {
    fn meta(&self) -> Meta {
        Meta {
            scheme: "ML-DSA-65",
            name: BACKEND,
        }
    }

    fn measure(&self, b: &Budget) -> Row {
        let (sk, vk, sig) = generate();
        let keygen = timing::measure(
            || {
                let mut seed = [0u8; mldsa::SEED_LENGTH];
                OsRng.fill_bytes(&mut seed);
                mldsa::SigningKeySeed::from(seed).expand()
            },
            b,
        );

        // Hedged signing draws fresh rnd per signature; aws-lc does that
        // inside its sign, so the draw stays inside the timed closure here too
        let mut j = 0u64;
        let sign = timing::measure(
            || {
                j += 1;
                let mut rnd = [0u8; mldsa::RND_LENGTH];
                OsRng.fill_bytes(&mut rnd);
                sk.sign(&sign_msg(j), b"", &rnd)
                    .expect("the empty context cannot exceed the length limit")
            },
            b,
        );

        let verify = timing::measure(|| vk.verify(MSG, b"", &sig).is_ok(), b);

        Row {
            meta: self.meta(),
            pk_len: mldsa::PUBLIC_KEY_LENGTH,
            sig_len: mldsa::SIGNATURE_LENGTH,
            sk_len: Some(mldsa::SEED_LENGTH),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let (_, vk, sig) = generate();
        vk.verify(MSG, b"", &sig).is_ok() && vk.verify(b"tampered", b"", &sig).is_err()
    }
}

// `$api` is an ident (`mldsa44`), not a path: `use $path::Item;` is a parse
// error for path fragments unless the item is braced, and rustfmt strips the
// braces from single-item imports. `use mldsa::$ident::Item;` survives both.
macro_rules! mysten_level_row {
    ($struct:ident, $scheme:literal, $api:ident) => {
        pub struct $struct;
        impl Scheme for $struct {
            fn meta(&self) -> Meta {
                Meta {
                    scheme: $scheme,
                    name: BACKEND,
                }
            }

            fn measure(&self, b: &Budget) -> Row {
                use mldsa::$api::{SigningKeySeed, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
                let mut seed = [0u8; mldsa::SEED_LENGTH];
                OsRng.fill_bytes(&mut seed);
                let (sk, vk) = SigningKeySeed::from(seed).expand();
                let mut rnd = [0u8; mldsa::RND_LENGTH];
                OsRng.fill_bytes(&mut rnd);
                let sig = sk.sign(MSG, b"", &rnd).expect("empty ctx");

                let keygen = timing::measure(
                    || {
                        let mut seed = [0u8; mldsa::SEED_LENGTH];
                        OsRng.fill_bytes(&mut seed);
                        SigningKeySeed::from(seed).expand()
                    },
                    b,
                );
                let mut j = 0u64;
                let sign = timing::measure(
                    || {
                        j += 1;
                        let mut rnd = [0u8; mldsa::RND_LENGTH];
                        OsRng.fill_bytes(&mut rnd);
                        sk.sign(&sign_msg(j), b"", &rnd).expect("empty ctx")
                    },
                    b,
                );
                let verify = timing::measure(|| vk.verify(MSG, b"", &sig).is_ok(), b);

                Row {
                    meta: self.meta(),
                    pk_len: PUBLIC_KEY_LENGTH,
                    sig_len: SIGNATURE_LENGTH,
                    sk_len: Some(mldsa::SEED_LENGTH),
                    keygen: Some(keygen),
                    sign: Some(sign),
                    verify,
                }
            }

            fn self_check(&self) -> bool {
                use mldsa::$api::SigningKeySeed;
                let mut seed = [0u8; mldsa::SEED_LENGTH];
                OsRng.fill_bytes(&mut seed);
                let (sk, vk) = SigningKeySeed::from(seed).expand();
                let mut rnd = [0u8; mldsa::RND_LENGTH];
                OsRng.fill_bytes(&mut rnd);
                let sig = sk.sign(MSG, b"", &rnd).expect("empty ctx");
                vk.verify(MSG, b"", &sig).is_ok() && vk.verify(b"tampered", b"", &sig).is_err()
            }
        }
    };
}

mysten_level_row!(MlDsa44Mysten, "ML-DSA-44", mldsa44);
mysten_level_row!(MlDsa87Mysten, "ML-DSA-87", mldsa87);

/// Interop gate for the head-to-head: each library must accept the other's
/// signatures.
pub fn cross_check_with_aws_lc() -> bool {
    use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
    use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};

    // Our signature under aws-lc's verifier.
    let (sk, vk, _) = generate();
    let mut rnd = [0u8; mldsa::RND_LENGTH];
    OsRng.fill_bytes(&mut rnd);
    let sig = sk
        .sign(MSG, b"", &rnd)
        .expect("the empty context cannot exceed the length limit");
    let ours_under_aws = UnparsedPublicKey::new(&ML_DSA_65, vk.as_bytes().as_slice())
        .verify(MSG, sig.as_bytes())
        .is_ok();

    let aws_rejects = UnparsedPublicKey::new(&ML_DSA_65, vk.as_bytes().as_slice())
        .verify(b"tampered", sig.as_bytes())
        .is_err();

    // aws-lc's signature under our verifier.
    let kp = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("aws-lc keygen");
    let mut buf = vec![0u8; mldsa::SIGNATURE_LENGTH];
    let n = kp.sign(MSG, &mut buf).expect("aws-lc sign");
    let theirs_under_ours = n == mldsa::SIGNATURE_LENGTH
        && mldsa::VerifyingKey::from_bytes(kp.public_key().as_ref())
            .and_then(|vk| mldsa::Signature::from_bytes(&buf).map(|sig| (vk, sig)))
            .map(|(vk, sig)| vk.verify(MSG, b"", &sig).is_ok())
            .unwrap_or(false);

    ours_under_aws && aws_rejects && theirs_under_ours
}
