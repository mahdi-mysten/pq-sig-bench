// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! FN-DSA (Falcon), one row per parameter set.
//!
//! FN-DSA-512 is measured through `fastcrypto::falcon512`'s public API on the
//! `mahdi/fn-dsa-512` branch: verify is the in-crate Montgomery-NTT port in
//! strict canonical mode; keygen and sign (behind `falcon-sign`) delegate to
//! PQClean's portable `falcon-padded-512` C, and sign re-verifies every
//! signature through the strict verifier before returning it. The sign number
//! therefore includes that gate — the cost of the API as shipped, not of the
//! raw C signer.
//!
//! FN-DSA-1024 has no fastcrypto implementation, so all three operations come
//! from PQClean's portable C (`falcon-padded-1024`). Both rows use the padded
//! fixed-size signature format.

use crate::{sign_msg, timing, Budget, Meta, Row, Scheme, MSG};
use fastcrypto::falcon512::{
    Falcon512KeyPair, Falcon512PublicKey, Falcon512Signature, FALCON512_PRIVATE_KEY_LENGTH,
    FALCON512_PUBLIC_KEY_LENGTH, FALCON512_SIGNATURE_LENGTH,
};
use fastcrypto::traits::{KeyPair as _, Signer as _, ToFromBytes as _, VerifyingKey as _};
use pqcrypto_falcon::{falconpadded1024 as f1024, falconpadded512 as f512};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use rand::{rngs::StdRng, SeedableRng as _};

// === FN-DSA-512: fastcrypto ===

pub struct Falcon512Fastcrypto;

impl Scheme for Falcon512Fastcrypto {
    fn meta(&self) -> Meta {
        Meta {
            scheme: "FN-DSA-512",
            name: "fastcrypto",
        }
    }

    fn measure(&self, b: &Budget) -> Row {
        // The rng is unused by this scheme's `generate` (PQClean draws its
        // own OS randomness); seeded only for symmetry with the other rows.
        let mut rng = StdRng::from_seed([7u8; 32]);
        let kp = Falcon512KeyPair::generate(&mut rng);
        let sig = kp.sign(MSG);

        let keygen = timing::measure(
            || Falcon512KeyPair::generate(&mut rng),
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
            pk_len: FALCON512_PUBLIC_KEY_LENGTH,
            sig_len: FALCON512_SIGNATURE_LENGTH,
            sk_len: Some(FALCON512_PRIVATE_KEY_LENGTH),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let mut rng = StdRng::from_seed([7u8; 32]);
        let kp = Falcon512KeyPair::generate(&mut rng);
        let sig = kp.sign(MSG);
        let roundtrip = kp.public().verify(MSG, &sig).is_ok();
        let tampered = kp.public().verify(b"tampered", &sig).is_err();

        // Interop gate against the C reference, both directions: fastcrypto's
        // signature must verify under PQClean, and a PQClean signature under
        // fastcrypto's strict verifier. Without this the row could time a
        // verifier that accepts only its own signer's quirks.
        let (Ok(c_pk), Ok(c_sig)) = (
            f512::PublicKey::from_bytes(kp.public().as_ref()),
            f512::DetachedSignature::from_bytes(sig.as_ref()),
        ) else {
            return false;
        };
        let ours_under_c = f512::verify_detached_signature(&c_sig, MSG, &c_pk).is_ok();

        let (pq_pk, pq_sk) = f512::keypair();
        let pq_sig = f512::detached_sign(MSG, &pq_sk);
        let theirs_under_us = match (
            Falcon512PublicKey::from_bytes(pq_pk.as_bytes()),
            Falcon512Signature::from_bytes(pq_sig.as_bytes()),
        ) {
            (Ok(pk), Ok(s)) => pk.verify(MSG, &s).is_ok(),
            _ => false,
        };

        roundtrip && tampered && ours_under_c && theirs_under_us
    }
}

// === FN-DSA-1024: PQClean C (falcon-padded-1024) ===

pub struct Falcon1024PqClean;

impl Scheme for Falcon1024PqClean {
    fn meta(&self) -> Meta {
        Meta {
            scheme: "FN-DSA-1024",
            name: "PQClean C",
        }
    }

    fn measure(&self, b: &Budget) -> Row {
        let (pk, sk) = f1024::keypair();
        let sig = f1024::detached_sign(MSG, &sk);

        let keygen = timing::measure(f1024::keypair, b.warmup, b.offchain_iters);
        let mut i = 0u64;
        let sign = timing::measure(
            || {
                i += 1;
                f1024::detached_sign(&sign_msg(i), &sk)
            },
            b.warmup,
            b.offchain_iters,
        );
        let verify = timing::measure(
            || f1024::verify_detached_signature(&sig, MSG, &pk).is_ok(),
            b.warmup,
            b.verify_iters,
        );

        Row {
            meta: self.meta(),
            pk_len: f1024::public_key_bytes(),
            sig_len: f1024::signature_bytes(),
            sk_len: Some(f1024::secret_key_bytes()),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let (pk, sk) = f1024::keypair();
        let sig = f1024::detached_sign(MSG, &sk);
        f1024::verify_detached_signature(&sig, MSG, &pk).is_ok()
            && f1024::verify_detached_signature(&sig, b"tampered", &pk).is_err()
    }
}
