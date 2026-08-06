// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! SLH-DSA-SHA2-128s through fastcrypto's sphincs module (pure Rust, behind
//! the `experimental` feature). The stateless hash-based alternative: its
//! security reduces to SHA-256 alone, with no lattice assumption, priced as
//! a 7,856-byte signature and signing measured in hundreds of milliseconds.
//! That signing cost is exactly what the timer's adaptive iteration count
//! exists for.
//!
//! 128s ("small") rather than 128f ("fast"): on-chain the signature is what
//! gets stored and verified, so the small-signature/slow-sign end of the
//! trade is the relevant one, and 128s also verifies faster than 128f.

use crate::{sign_msg, timing, Budget, Meta, Row, Scheme, MSG};
use fastcrypto::sphincs::{
    slh_keygen, slh_sign, slh_verify, SlhDsaParams, SlhDsaPublicKey, SlhDsaSecretKey,
    SlhDsaSignature,
};
use rand::rngs::OsRng;
use rand::RngCore as _;

/// n = 16 bytes for the 128-bit security category (FIPS 205 Table 2).
const N: usize = 16;

fn fresh_seed() -> [u8; N] {
    let mut s = [0u8; N];
    OsRng.fill_bytes(&mut s);
    s
}

/// Keygen with fresh OS randomness for all three seeds; `slh_keygen` itself
/// is deterministic in its inputs (FIPS 205 Alg. 18 with the seed draw
/// hoisted to the caller), so the draw belongs inside the timed closure to
/// match the other rows.
fn keygen(p: &SlhDsaParams) -> (SlhDsaPublicKey, SlhDsaSecretKey) {
    slh_keygen(p, &fresh_seed(), &fresh_seed(), &fresh_seed())
}

pub struct SlhDsa128sFastcrypto;

impl Scheme for SlhDsa128sFastcrypto {
    fn meta(&self) -> Meta {
        Meta {
            scheme: "SLH-DSA-SHA2-128s",
            name: "fastcrypto sphincs",
        }
    }

    fn measure(&self, b: &Budget) -> Row {
        let p = SlhDsaParams::sha2_128s();
        let (pk, sk) = keygen(&p);
        let sig = slh_sign(&p, &sk, MSG, b"", Some(&fresh_seed()))
            .expect("the empty context cannot exceed the length limit");

        let keygen = timing::measure(|| keygen(&p), b);

        // Hedged signing, fresh addrnd per signature, matching how the
        // ML-DSA rows draw rnd inside the timed closure.
        let mut i = 0u64;
        let sign = timing::measure(
            || {
                i += 1;
                slh_sign(&p, &sk, &sign_msg(i), b"", Some(&fresh_seed()))
                    .expect("the empty context cannot exceed the length limit")
            },
            b,
        );

        let verify = timing::measure(|| slh_verify(&p, &pk, MSG, &sig, b""), b);

        Row {
            meta: self.meta(),
            // pk = pk_seed ‖ pk_root, sk = sk_seed ‖ sk_prf ‖ pk_seed ‖
            // pk_root (FIPS 205 §9.1).
            pk_len: 2 * N,
            sig_len: SlhDsaSignature::expected_len(&p),
            sk_len: Some(4 * N),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let p = SlhDsaParams::sha2_128s();
        let (pk, sk) = keygen(&p);
        let Ok(sig) = slh_sign(&p, &sk, MSG, b"", Some(&fresh_seed())) else {
            return false;
        };

        // Byte roundtrip before the semantic checks: the serialized length
        // must match what the table's sig column claims, and the parsed-back
        // signature must still verify, so the sizes reported are the sizes
        // of a real wire encoding.
        let bytes = sig.to_bytes();
        if bytes.len() != SlhDsaSignature::expected_len(&p) {
            return false;
        }
        let Ok(sig2) = SlhDsaSignature::from_bytes(&p, &bytes) else {
            return false;
        };

        slh_verify(&p, &pk, MSG, &sig2, b"") && !slh_verify(&p, &pk, b"tampered", &sig, b"")
    }
}
