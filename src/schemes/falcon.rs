// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Falcon-512: one signature format, two rows. "Falcon-512" times the
//! shipping verifier — `fastcrypto::falcon512`'s public strict verify, backed
//! by the Montgomery-NTT core. The PQClean C row is kept because it runs the
//! same math over the same bytes, so the cost delta isolates implementation
//! style alone: hand-optimized Rust with precomputed Montgomery tables vs
//! PQClean's deliberately portable "clean" C. Both rows time verification of
//! the identical signature bytes; without that, a backend could look faster
//! merely because it was handed different input.

use crate::{timing, Budget, Meta, Row, Scheme, MSG};
use fastcrypto::falcon512::{
    Falcon512PublicKey, Falcon512Signature, FALCON512_PUBLIC_KEY_LENGTH, FALCON512_SIGNATURE_LENGTH,
};
use fastcrypto::traits::{ToFromBytes, VerifyingKey};
use pqcrypto_falcon::falconpadded512 as f512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use std::sync::OnceLock;

/// The shared (pk, sig) pair both Falcon rows verify: one PQClean
/// `falconpadded512` pair over [`MSG`], generated once. PQClean emits the
/// canonical padded form (666 bytes, header 0x39) that fastcrypto's strict
/// verify accepts; the PQClean row's self_check cross-verifies it under
/// fastcrypto, so the rows are proven to measure the same math before any
/// timing is trusted.
fn shared_triple() -> &'static (Vec<u8>, Vec<u8>) {
    static TRIPLE: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    TRIPLE.get_or_init(|| {
        let (pk, sk) = f512::keypair();
        let sig = f512::detached_sign(MSG, &sk);
        (pk.as_bytes().to_vec(), sig.as_bytes().to_vec())
    })
}

fn falcon_meta(name: &'static str) -> Meta {
    Meta { name }
}

fn parsed_triple() -> (Falcon512PublicKey, Falcon512Signature) {
    let (pk, sig) = shared_triple();
    (
        Falcon512PublicKey::from_bytes(pk).expect("PQClean public key parses"),
        Falcon512Signature::from_bytes(sig).expect("PQClean padded signature parses"),
    )
}

// === Row 1: fastcrypto::falcon512 (Montgomery-NTT core) ===

pub struct Falcon512;

impl Scheme for Falcon512 {
    fn meta(&self) -> Meta {
        falcon_meta("Falcon-512")
    }

    fn measure(&self, b: &Budget) -> Row {
        let (pk, sig) = parsed_triple();
        let verify = timing::measure(|| pk.verify(MSG, &sig).is_ok(), b.warmup, b.verify_iters);
        // Verify-only by design (signing carries Falcon's FP sampler and
        // never runs on validators), so no keygen/sign cells.
        Row {
            meta: self.meta(),
            pk_len: FALCON512_PUBLIC_KEY_LENGTH,
            sig_len: FALCON512_SIGNATURE_LENGTH,
            sk_len: None,
            keygen: None,
            sign: None,
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let (pk, sig) = parsed_triple();
        pk.verify(MSG, &sig).is_ok() && pk.verify(b"tampered", &sig).is_err()
    }
}

// === Row 2: PQClean C (pqcrypto-falcon, falconpadded512) ===

pub struct Falcon512PqClean;

impl Scheme for Falcon512PqClean {
    fn meta(&self) -> Meta {
        falcon_meta("Falcon-512 (PQClean C)")
    }

    fn measure(&self, b: &Budget) -> Row {
        let (pk_bytes, sig_bytes) = shared_triple();
        let pk = f512::PublicKey::from_bytes(pk_bytes).expect("shared pk parses");
        let sig = f512::DetachedSignature::from_bytes(sig_bytes).expect("shared sig parses");

        // Keygen/sign cost doesn't depend on the key, so a fresh keypair is
        // fine here; verify must use the shared triple.
        let (_, sk) = f512::keypair();
        let keygen = timing::measure(f512::keypair, b.warmup, b.offchain_iters);
        let sign = timing::measure(|| f512::detached_sign(MSG, &sk), b.warmup, b.offchain_iters);
        let verify = timing::measure(
            || f512::verify_detached_signature(&sig, MSG, &pk).is_ok(),
            b.warmup,
            b.verify_iters,
        );

        Row {
            meta: self.meta(),
            pk_len: f512::public_key_bytes(),
            sig_len: f512::signature_bytes(),
            sk_len: Some(f512::secret_key_bytes()),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let (pk_bytes, sig_bytes) = shared_triple();
        let (Ok(pk), Ok(sig)) = (
            f512::PublicKey::from_bytes(pk_bytes),
            f512::DetachedSignature::from_bytes(sig_bytes),
        ) else {
            return false;
        };
        let roundtrip = f512::verify_detached_signature(&sig, MSG, &pk).is_ok();
        let tampered = f512::verify_detached_signature(&sig, b"tampered", &pk).is_err();

        // Interop gate: the shared PQClean signature must also verify under
        // fastcrypto's verifier, otherwise the two rows are not measuring the
        // same signature format and the comparison is meaningless.
        let (fc_pk, fc_sig) = parsed_triple();
        let interop = fc_pk.verify(MSG, &fc_sig).is_ok();

        roundtrip && tampered && interop
    }
}
