// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 baseline, measured through fastcrypto's own scheme so the ratio
//! reflects what a Sui validator actually runs today. Single verification
//! only: fastcrypto also batch-verifies Ed25519 (~2x amortized on validators),
//! and no PQ scheme has a batch mode, so the single-verify ratio understates
//! the real gap by about that factor.

use crate::{sign_msg, timing, Budget, Meta, Row, Scheme, MSG};
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{Authenticator, KeyPair, Signer, SigningKey, VerifyingKey};
use rand::{rngs::StdRng, SeedableRng as _};

pub struct Ed25519Baseline;

impl Scheme for Ed25519Baseline {
    fn meta(&self) -> Meta {
        Meta {
            scheme: "Ed25519",
            name: "fastcrypto (baseline)",
        }
    }

    fn measure(&self, b: &Budget) -> Row {
        let mut rng = StdRng::from_seed([7u8; 32]);
        let kp = Ed25519KeyPair::generate(&mut rng);
        let sig = kp.sign(MSG);

        let keygen = timing::measure(
            || Ed25519KeyPair::generate(&mut rng),
            b.warmup,
            b.offchain_iters,
        );
        let mut i = 0u64;
        let sign = timing::measure(
            || {
                i += 1;
                kp.sign(&sign_msg(i))
            },
            b.warmup,
            b.offchain_iters,
        );
        let verify = timing::measure(
            || kp.public().verify(MSG, &sig).is_ok(),
            b.warmup,
            b.verify_iters,
        );

        Row {
            meta: self.meta(),
            pk_len: <Ed25519KeyPair as KeyPair>::PubKey::LENGTH,
            sig_len: <Ed25519KeyPair as KeyPair>::Sig::LENGTH,
            sk_len: Some(<Ed25519KeyPair as KeyPair>::PrivKey::LENGTH),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let mut rng = StdRng::from_seed([7u8; 32]);
        let kp = Ed25519KeyPair::generate(&mut rng);
        let sig = kp.sign(MSG);
        kp.public().verify(MSG, &sig).is_ok() && kp.public().verify(b"tampered", &sig).is_err()
    }
}
