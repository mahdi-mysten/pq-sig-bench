// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Phase 2: ML-DSA-65 across the Rust implementation landscape.
//!
//! Phase 1 compared schemes; the scheme decision is made (ML-DSA-65). The
//! question this module answers is implementation choice: how does our
//! wrapper compare against the other ways a Rust project can get ML-DSA-65
//! today?
//!
//! Contenders, each cross-verified against the wrapper before timing:
//! - aws-lc-rs: mldsa-native C imported into AWS-LC. This is what NEAR's
//!   near-crypto uses for its mainnet ML-DSA-65 accounts, so this pair is a
//!   direct read on how our timings compare with NEAR's.
//! - ml-dsa (RustCrypto): pure Rust.
//! - libcrux-ml-dsa (Cryspen): formally verified Rust, own SIMD backends.
//! - pqcrypto-mldsa: PQClean's portable reference C behind bindings.
//!
//! Each contender is timed on its own under the same [`Budget`] as every
//! other report row; the report references the numbers against its own
//! mysten ML-DSA-65 row from the same run, not against paired deltas.

use crate::schemes::mldsa_mysten;
use crate::{sign_msg, timing, Budget, Timing, MSG};

use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};
use mysten_mldsa_native_rs as wrapper;
use rand::rngs::OsRng;
use rand::RngCore;

fn fresh_seed() -> [u8; wrapper::SEED_LENGTH] {
    let mut seed = [0u8; wrapper::SEED_LENGTH];
    OsRng.fill_bytes(&mut seed);
    seed
}

/// Times keygen/sign/verify for each contender under the report's shared
/// budget; returns `(name, keygen, sign, verify)` per contender. Every
/// contender must pass its cross-verification against the wrapper before
/// anything is timed.
pub fn measure_contenders(b: &Budget) -> Vec<(String, Timing, Timing, Timing)> {
    let (_, m_vk, m_sig) = mldsa_mysten::generate();
    let mut results: Vec<(String, Timing, Timing, Timing)> = Vec::new();

    // ---- aws-lc-rs (what NEAR's near-crypto uses) --------------------------
    {
        assert!(
            mldsa_mysten::cross_check_with_aws_lc(),
            "aws-lc-rs cross-verification failed"
        );
        let a_kp = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("aws-lc keygen");
        let a_pk = a_kp.public_key().as_ref().to_vec();
        let mut a_sig = vec![0u8; wrapper::SIGNATURE_LENGTH];
        a_kp.sign(MSG, &mut a_sig).expect("aws-lc sign");
        let a_upk = UnparsedPublicKey::new(&ML_DSA_65, a_pk.as_slice());

        let keygen = timing::measure(|| PqdsaKeyPair::generate(&ML_DSA_65_SIGNING), b);
        let mut j = 0u64;
        let mut sig_buf = vec![0u8; wrapper::SIGNATURE_LENGTH];
        let sign = timing::measure(
            || {
                j += 1;
                a_kp.sign(&sign_msg(j), &mut sig_buf)
            },
            b,
        );
        let verify = timing::measure(|| a_upk.verify(MSG, &a_sig).is_ok(), b);
        results.push(("aws-lc-rs (NEAR pick)".to_string(), keygen, sign, verify));
    }

    // ---- ml-dsa (RustCrypto, pure Rust) ------------------------------------
    {
        use ml_dsa::signature::Verifier as _;
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, SigningKey};

        // Cross-check both directions before timing anything.
        let rc_sk = SigningKey::<MlDsa65>::from_seed(&fresh_seed().into());
        let sig = rc_sk
            .expanded_key()
            .sign_deterministic(MSG, b"")
            .expect("sign");
        let vk_bytes = rc_sk.expanded_key().verifying_key().encode();
        let ours_vk = wrapper::VerifyingKey::from_bytes(vk_bytes.as_ref()).expect("pk len");
        let ours_sig = wrapper::Signature::from_bytes(sig.encode().as_ref()).expect("sig len");
        assert!(
            ours_vk.verify(MSG, b"", &ours_sig).is_ok(),
            "wrapper rejects RustCrypto signature"
        );
        let their_vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(
            &EncodedVerifyingKey::<MlDsa65>::try_from(m_vk.as_bytes().as_ref()).unwrap(),
        );
        let their_sig = ml_dsa::Signature::<MlDsa65>::decode(
            &EncodedSignature::<MlDsa65>::try_from(m_sig.as_bytes().as_ref()).unwrap(),
        )
        .expect("signature decodes");
        assert!(
            their_vk.verify(MSG, &their_sig).is_ok(),
            "RustCrypto rejects wrapper signature"
        );

        let keygen = timing::measure(|| SigningKey::<MlDsa65>::from_seed(&fresh_seed().into()), b);
        let mut j = 0u64;
        // sign_deterministic: same rejection-sampling work as the hedged
        // variant, rnd is derived instead of drawn; avoids the rand_core 0.9
        // requirement of sign_randomized.
        let sign = timing::measure(
            || {
                j += 1;
                rc_sk
                    .expanded_key()
                    .sign_deterministic(&sign_msg(j), b"")
                    .expect("sign")
            },
            b,
        );
        let verify = timing::measure(|| their_vk.verify(MSG, &their_sig).is_ok(), b);
        results.push(("ml-dsa (RustCrypto)".to_string(), keygen, sign, verify));
    }

    // ---- libcrux-ml-dsa (Cryspen, formally verified) -----------------------
    {
        use libcrux_ml_dsa::ml_dsa_65 as lc;

        let kp = lc::generate_key_pair(fresh_seed());
        let sig = lc::sign(&kp.signing_key, MSG, b"", fresh_seed()).expect("sign");
        let ours_vk =
            wrapper::VerifyingKey::from_bytes(kp.verification_key.as_ref()).expect("pk len");
        let ours_sig = wrapper::Signature::from_bytes(sig.as_ref()).expect("sig len");
        assert!(
            ours_vk.verify(MSG, b"", &ours_sig).is_ok(),
            "wrapper rejects libcrux signature"
        );
        let their_vk = libcrux_ml_dsa::MLDSAVerificationKey::new(*m_vk.as_bytes());
        let their_sig = libcrux_ml_dsa::MLDSASignature::new(*m_sig.as_bytes());
        assert!(
            lc::verify(&their_vk, MSG, b"", &their_sig).is_ok(),
            "libcrux rejects wrapper signature"
        );

        let keygen = timing::measure(|| lc::generate_key_pair(fresh_seed()), b);
        let mut j = 0u64;
        let sign = timing::measure(
            || {
                j += 1;
                let mut rnd = [0u8; 32];
                OsRng.fill_bytes(&mut rnd);
                lc::sign(&kp.signing_key, &sign_msg(j), b"", rnd).expect("sign")
            },
            b,
        );
        let verify = timing::measure(|| lc::verify(&their_vk, MSG, b"", &their_sig).is_ok(), b);
        results.push(("libcrux-ml-dsa".to_string(), keygen, sign, verify));
    }

    // ---- pqcrypto-mldsa (PQClean reference C) ------------------------------
    {
        use pqcrypto_mldsa::mldsa65 as pq;
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

        let (pk, sk) = pq::keypair();
        let sig = pq::detached_sign(MSG, &sk);
        let ours_vk = wrapper::VerifyingKey::from_bytes(pk.as_bytes()).expect("pk len");
        let ours_sig = wrapper::Signature::from_bytes(sig.as_bytes()).expect("sig len");
        assert!(
            ours_vk.verify(MSG, b"", &ours_sig).is_ok(),
            "wrapper rejects PQClean signature"
        );
        let their_pk = pq::PublicKey::from_bytes(m_vk.as_bytes()).expect("pk len");
        let their_sig = pq::DetachedSignature::from_bytes(m_sig.as_bytes()).expect("sig len");
        assert!(
            pq::verify_detached_signature(&their_sig, MSG, &their_pk).is_ok(),
            "PQClean rejects wrapper signature"
        );

        let keygen = timing::measure(pq::keypair, b);
        let mut j = 0u64;
        let sign = timing::measure(
            || {
                j += 1;
                pq::detached_sign(&sign_msg(j), &sk)
            },
            b,
        );
        let verify = timing::measure(
            || pq::verify_detached_signature(&their_sig, MSG, &their_pk).is_ok(),
            b,
        );
        results.push(("pqcrypto-mldsa (PQClean)".to_string(), keygen, sign, verify));
    }

    results
}
