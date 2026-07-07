// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA-44 (FIPS 204): one signature format, five implementations. FIPS 204
//! fixes the byte encodings (pk 1312, sig 2420), so every row verifies the
//! identical (pk, sig) pair, generated once by libcrux with a fixed seed and
//! deterministic signing. libcrux is the core the fastcrypto `mldsa44` module
//! wraps, so its row doubles as the fastcrypto number until that module lands
//! on the branch.
//!
//! Sign rows are deterministic where the API offers it (libcrux, RustCrypto,
//! fips204 via a fixed hedging seed); PQClean and aws-lc-rs sign hedged. The
//! difference is one 32-byte RNG draw, noise at these costs.

use crate::{sign_msg, timing, Budget, Meta, Row, Scheme, MSG};
use rand::SeedableRng as _;
use std::sync::OnceLock;

const PK_LEN: usize = 1312;
const SIG_LEN: usize = 2420;

fn meta(name: &'static str) -> Meta {
    Meta {
        scheme: "ML-DSA-44",
        name,
    }
}

/// Fixed keygen seed for the shared pair; deterministic so reruns compare.
const SEED: [u8; 32] = [7u8; 32];

/// The shared (pk, sig) every row verifies: libcrux keygen from [`SEED`],
/// deterministic sign over [`MSG`] with an empty context.
fn shared_pair() -> &'static (Vec<u8>, Vec<u8>) {
    static PAIR: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    PAIR.get_or_init(|| {
        use libcrux_ml_dsa::ml_dsa_44::portable;
        let kp = portable::generate_key_pair(SEED);
        let sig = portable::sign(&kp.signing_key, MSG, b"", [0u8; 32])
            .expect("libcrux deterministic sign");
        assert_eq!(kp.verification_key.as_slice().len(), PK_LEN);
        assert_eq!(sig.as_slice().len(), SIG_LEN);
        (
            kp.verification_key.as_slice().to_vec(),
            sig.as_slice().to_vec(),
        )
    })
}

/// Per-iteration keygen seed
fn seed(i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

// === libcrux ml-dsa ===

pub struct MlDsa44Libcrux;

impl Scheme for MlDsa44Libcrux {
    fn meta(&self) -> Meta {
        meta("libcrux")
    }

    fn measure(&self, b: &Budget) -> Row {
        use libcrux_ml_dsa::ml_dsa_44::portable;
        use libcrux_ml_dsa::ml_dsa_44::{MLDSA44Signature, MLDSA44VerificationKey};

        let (pk_bytes, sig_bytes) = shared_pair();
        let vk = MLDSA44VerificationKey::new(pk_bytes.as_slice().try_into().unwrap());
        let sig = MLDSA44Signature::new(sig_bytes.as_slice().try_into().unwrap());
        let kp = portable::generate_key_pair(SEED);

        let mut i = 0u64;
        let keygen = timing::measure(
            || {
                i += 1;
                portable::generate_key_pair(seed(i))
            },
            b.warmup,
            b.offchain_iters,
        );
        let mut j = 0u64;
        let sign = timing::measure(
            || {
                j += 1;
                portable::sign(&kp.signing_key, &sign_msg(j), b"", [0u8; 32])
            },
            b.warmup,
            b.offchain_iters,
        );
        let verify = timing::measure(
            || portable::verify(&vk, MSG, b"", &sig).is_ok(),
            b.warmup,
            b.verify_iters,
        );

        Row {
            meta: self.meta(),
            pk_len: PK_LEN,
            sig_len: SIG_LEN,
            sk_len: Some(kp.signing_key.as_slice().len()),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        use libcrux_ml_dsa::ml_dsa_44::portable;
        use libcrux_ml_dsa::ml_dsa_44::{MLDSA44Signature, MLDSA44VerificationKey};
        let (pk_bytes, sig_bytes) = shared_pair();
        let vk = MLDSA44VerificationKey::new(pk_bytes.as_slice().try_into().unwrap());
        let sig = MLDSA44Signature::new(sig_bytes.as_slice().try_into().unwrap());
        portable::verify(&vk, MSG, b"", &sig).is_ok()
            && portable::verify(&vk, b"tampered", b"", &sig).is_err()
    }
}

// === RustCrypto ml-dsa ===

pub struct MlDsa44RustCrypto;

impl MlDsa44RustCrypto {
    fn parsed(
        &self,
    ) -> (
        ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
        ml_dsa::Signature<ml_dsa::MlDsa44>,
    ) {
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa44, Signature, VerifyingKey};
        let (pk_bytes, sig_bytes) = shared_pair();
        let enc_vk = EncodedVerifyingKey::<MlDsa44>::try_from(pk_bytes.as_slice())
            .expect("shared pk parses");
        let enc_sig =
            EncodedSignature::<MlDsa44>::try_from(sig_bytes.as_slice()).expect("shared sig parses");
        (
            VerifyingKey::<MlDsa44>::decode(&enc_vk),
            Signature::<MlDsa44>::decode(&enc_sig).expect("shared sig decodes"),
        )
    }
}

impl Scheme for MlDsa44RustCrypto {
    fn meta(&self) -> Meta {
        meta("RustCrypto ml-dsa")
    }

    fn measure(&self, b: &Budget) -> Row {
        use ml_dsa::{MlDsa44, SigningKey};

        let (vk, sig) = self.parsed();
        // from_seed is ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6), the same
        // entry point the other keygen rows time.
        let sk = SigningKey::<MlDsa44>::from_seed(&SEED.into());

        let mut i = 0u64;
        let keygen = timing::measure(
            || {
                i += 1;
                SigningKey::<MlDsa44>::from_seed(&seed(i).into())
            },
            b.warmup,
            b.offchain_iters,
        );
        let mut j = 0u64;
        let sign = timing::measure(
            || {
                j += 1;
                sk.expanded_key().sign_deterministic(&sign_msg(j), b"")
            },
            b.warmup,
            b.offchain_iters,
        );
        let verify = timing::measure(
            || vk.verify_with_context(MSG, b"", &sig),
            b.warmup,
            b.verify_iters,
        );

        Row {
            meta: self.meta(),
            pk_len: PK_LEN,
            sig_len: SIG_LEN,
            // The crate's native private-key form is the 32-byte seed.
            sk_len: Some(32),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let (vk, sig) = self.parsed();
        vk.verify_with_context(MSG, b"", &sig) && !vk.verify_with_context(b"tampered", b"", &sig)
    }
}

// === fips204 (integritychain) ===

pub struct MlDsa44Fips204;

impl Scheme for MlDsa44Fips204 {
    fn meta(&self) -> Meta {
        meta("fips204")
    }

    fn measure(&self, b: &Budget) -> Row {
        use fips204::ml_dsa_44 as f204;
        use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};

        let (pk_bytes, sig_bytes) = shared_pair();
        let pk = f204::PublicKey::try_from_bytes(pk_bytes.as_slice().try_into().unwrap())
            .expect("shared pk parses");
        let sig: [u8; f204::SIG_LEN] = sig_bytes.as_slice().try_into().unwrap();
        let mut kg_rng = rand::rngs::StdRng::from_seed(SEED);
        let (_, sk) = f204::KG::try_keygen_with_rng(&mut kg_rng).expect("fips204 keygen");

        let keygen = timing::measure(f204::KG::try_keygen, b.warmup, b.offchain_iters);
        let mut j = 0u64;
        let sign = timing::measure(
            || {
                j += 1;
                sk.try_sign_with_seed(&[0u8; 32], &sign_msg(j), b"")
            },
            b.warmup,
            b.offchain_iters,
        );
        let verify = timing::measure(|| pk.verify(MSG, &sig, b""), b.warmup, b.verify_iters);

        Row {
            meta: self.meta(),
            pk_len: f204::PK_LEN,
            sig_len: f204::SIG_LEN,
            sk_len: Some(f204::SK_LEN),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        use fips204::ml_dsa_44 as f204;
        use fips204::traits::{SerDes as _, Verifier as _};
        let (pk_bytes, sig_bytes) = shared_pair();
        let Ok(pk) = f204::PublicKey::try_from_bytes(pk_bytes.as_slice().try_into().unwrap())
        else {
            return false;
        };
        let sig: [u8; f204::SIG_LEN] = sig_bytes.as_slice().try_into().unwrap();
        pk.verify(MSG, &sig, b"") && !pk.verify(b"tampered", &sig, b"")
    }
}

// === PQClean C (pqcrypto-mldsa) ===

pub struct MlDsa44PqClean;

impl Scheme for MlDsa44PqClean {
    fn meta(&self) -> Meta {
        meta("PQClean C")
    }

    fn measure(&self, b: &Budget) -> Row {
        use pqcrypto_mldsa::mldsa44 as pqc;
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

        let (pk_bytes, sig_bytes) = shared_pair();
        let pk = pqc::PublicKey::from_bytes(pk_bytes).expect("shared pk parses");
        let sig = pqc::DetachedSignature::from_bytes(sig_bytes).expect("shared sig parses");
        let (_, sk) = pqc::keypair();

        let keygen = timing::measure(pqc::keypair, b.warmup, b.offchain_iters);
        let mut j = 0u64;
        let sign = timing::measure(
            || {
                j += 1;
                pqc::detached_sign(&sign_msg(j), &sk)
            },
            b.warmup,
            b.offchain_iters,
        );
        let verify = timing::measure(
            || pqc::verify_detached_signature(&sig, MSG, &pk).is_ok(),
            b.warmup,
            b.verify_iters,
        );

        Row {
            meta: self.meta(),
            pk_len: pqc::public_key_bytes(),
            sig_len: pqc::signature_bytes(),
            sk_len: Some(pqc::secret_key_bytes()),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        use pqcrypto_mldsa::mldsa44 as pqc;
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
        let (pk_bytes, sig_bytes) = shared_pair();
        let (Ok(pk), Ok(sig)) = (
            pqc::PublicKey::from_bytes(pk_bytes),
            pqc::DetachedSignature::from_bytes(sig_bytes),
        ) else {
            return false;
        };
        pqc::verify_detached_signature(&sig, MSG, &pk).is_ok()
            && pqc::verify_detached_signature(&sig, b"tampered", &pk).is_err()
    }
}

// === aws-lc-rs (AWS-LC C; the audited/FIPS-track reference) ===

pub struct MlDsa44AwsLc;

impl Scheme for MlDsa44AwsLc {
    fn meta(&self) -> Meta {
        meta("aws-lc-rs")
    }

    fn measure(&self, b: &Budget) -> Row {
        use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
        use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_44, ML_DSA_44_SIGNING};

        let (pk_bytes, sig_bytes) = shared_pair();
        let upk = UnparsedPublicKey::new(&ML_DSA_44, pk_bytes.as_slice());
        let kp = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).expect("aws-lc keygen");
        let mut sig_buf = vec![0u8; SIG_LEN];

        let keygen = timing::measure(
            || PqdsaKeyPair::generate(&ML_DSA_44_SIGNING),
            b.warmup,
            b.offchain_iters,
        );
        let mut j = 0u64;
        let sign = timing::measure(
            || {
                j += 1;
                kp.sign(&sign_msg(j), &mut sig_buf)
            },
            b.warmup,
            b.offchain_iters,
        );
        let verify = timing::measure(
            || upk.verify(MSG, sig_bytes).is_ok(),
            b.warmup,
            b.verify_iters,
        );

        Row {
            meta: self.meta(),
            pk_len: kp.public_key().as_ref().len(),
            sig_len: SIG_LEN,
            // aws-lc stores the 32-byte seed as the raw private key.
            sk_len: Some(32),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
        use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_44, ML_DSA_44_SIGNING};

        // The shared libcrux signature must verify under AWS-LC.
        let (pk_bytes, sig_bytes) = shared_pair();
        let upk = UnparsedPublicKey::new(&ML_DSA_44, pk_bytes.as_slice());
        let interop =
            upk.verify(MSG, sig_bytes).is_ok() && upk.verify(b"tampered", sig_bytes).is_err();

        // And an AWS-LC-produced signature must verify under libcrux, so the
        // two sign paths are proven to emit the same format.
        let Ok(kp) = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING) else {
            return false;
        };
        let mut sig_buf = vec![0u8; SIG_LEN];
        let Ok(n) = kp.sign(MSG, &mut sig_buf) else {
            return false;
        };
        let own_pk: [u8; PK_LEN] = match kp.public_key().as_ref().try_into() {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let own_sig: [u8; SIG_LEN] = match sig_buf[..n].try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        use libcrux_ml_dsa::ml_dsa_44::{portable, MLDSA44Signature, MLDSA44VerificationKey};
        let vk = MLDSA44VerificationKey::new(own_pk);
        let sig = MLDSA44Signature::new(own_sig);
        let cross = portable::verify(&vk, MSG, b"", &sig).is_ok();

        interop && cross
    }
}
