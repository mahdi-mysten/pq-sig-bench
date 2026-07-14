// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ML-DSA (FIPS 204) at all three security levels, measured through
//! aws-lc-rs — the mldsa-native C imported by AWS-LC, behind the crate's
//! `unstable` feature. One row per parameter set; the API only signs hedged
//! (one 32-byte RNG draw per signature), noise at these costs.

use crate::{sign_msg, timing, Budget, Meta, Row, Scheme, MSG};
use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{
    PqdsaKeyPair, PqdsaSigningAlgorithm, PqdsaVerificationAlgorithm, ML_DSA_44, ML_DSA_44_SIGNING,
    ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING,
};

/// One aws-lc-rs row. The parameter sets differ only in the algorithm handles
/// and the FIPS 204 byte sizes, so one struct covers all three.
pub struct MlDsaAwsLc {
    scheme: &'static str,
    signing: &'static PqdsaSigningAlgorithm,
    verification: &'static PqdsaVerificationAlgorithm,
    /// FIPS 204 signature length, asserted against what aws-lc actually
    /// emits so a mismatched handle/size pairing fails loudly.
    sig_len: usize,
}

pub const ML_DSA_44_ROW: MlDsaAwsLc = MlDsaAwsLc {
    scheme: "ML-DSA-44",
    signing: &ML_DSA_44_SIGNING,
    verification: &ML_DSA_44,
    sig_len: 2420,
};

pub const ML_DSA_65_ROW: MlDsaAwsLc = MlDsaAwsLc {
    scheme: "ML-DSA-65",
    signing: &ML_DSA_65_SIGNING,
    verification: &ML_DSA_65,
    sig_len: 3309,
};

pub const ML_DSA_87_ROW: MlDsaAwsLc = MlDsaAwsLc {
    scheme: "ML-DSA-87",
    signing: &ML_DSA_87_SIGNING,
    verification: &ML_DSA_87,
    sig_len: 4627,
};

impl MlDsaAwsLc {
    /// Fresh key pair plus one signature over [`MSG`], as raw bytes.
    fn generate(&self) -> (PqdsaKeyPair, Vec<u8>, Vec<u8>) {
        let kp = PqdsaKeyPair::generate(self.signing).expect("aws-lc keygen");
        let pk = kp.public_key().as_ref().to_vec();
        let mut sig = vec![0u8; self.sig_len];
        let n = kp.sign(MSG, &mut sig).expect("aws-lc sign");
        assert_eq!(n, self.sig_len, "signature length is fixed by FIPS 204");
        (kp, pk, sig)
    }
}

impl Scheme for MlDsaAwsLc {
    fn meta(&self) -> Meta {
        Meta {
            scheme: self.scheme,
            name: "aws-lc-rs",
        }
    }

    fn measure(&self, b: &Budget) -> Row {
        let (kp, pk_bytes, sig_bytes) = self.generate();
        let upk = UnparsedPublicKey::new(self.verification, pk_bytes.as_slice());
        let mut sig_buf = vec![0u8; self.sig_len];

        let keygen = timing::measure(
            || PqdsaKeyPair::generate(self.signing),
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
            || upk.verify(MSG, &sig_bytes).is_ok(),
            b.warmup,
            b.verify_iters,
        );

        Row {
            meta: self.meta(),
            pk_len: pk_bytes.len(),
            sig_len: self.sig_len,
            // aws-lc stores the 32-byte seed as the raw private key.
            sk_len: Some(32),
            keygen: Some(keygen),
            sign: Some(sign),
            verify,
        }
    }

    fn self_check(&self) -> bool {
        let (_, pk_bytes, sig_bytes) = self.generate();
        let upk = UnparsedPublicKey::new(self.verification, pk_bytes.as_slice());
        upk.verify(MSG, &sig_bytes).is_ok() && upk.verify(b"tampered", &sig_bytes).is_err()
    }
}
