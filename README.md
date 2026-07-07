# pq-sig-bench

Verify-cost benchmarks for the post-quantum signature work in
[mahdi-mysten/fastcrypto (`pq-schemes`)](https://github.com/mahdi-mysten/fastcrypto/tree/pq-schemes).
Within each scheme the signature format is fixed by the standard, so every
row verifies the identical (pk, sig) bytes and the deltas isolate
implementation style alone. Each row passes a verify/tamper self-check
(including cross-implementation interop) before its timing is trusted.

Rows:

- **Ed25519 (baseline)** — fastcrypto's own scheme, i.e. what a Sui
  validator runs today. Single verification: fastcrypto also batch-verifies
  Ed25519 (~2× amortized), and no PQ scheme has a batch mode, so the
  single-verify ratios understate the real gap by about that factor.
- **FN-DSA-512 (Falcon)** — fastcrypto's Montgomery-NTT verifier against
  PQClean's reference C (`pqcrypto-falcon`). The fastcrypto row is
  verify-only (keygen/sign are wip).
- **ML-DSA-44** — five implementations of FIPS 204: `libcrux-ml-dsa`
  (Cryspen; portable path, the core fastcrypto's `mldsa44` module wraps),
  `ml-dsa` (RustCrypto), `fips204` (integritychain), `pqcrypto-mldsa`
  (PQClean C) and `aws-lc-rs` (AWS-LC; ML-DSA behind its `unstable`
  feature).

## Run

```
cargo run --release --bin report
```

Prints the report and writes `REPORT.md` and `results.csv` into the repo
root. Prerequisites: a Rust toolchain and cmake (`brew install cmake`) —
the first build compiles AWS-LC from source and takes a few minutes; after
that a run takes a few seconds. The fastcrypto dependency tracks the
`pq-schemes` branch on my fork; `cargo update -p fastcrypto` picks up new pushes.

## Method

- Median of 1000 iterations for verify and 100 for keygen/sign, fixed
  counts, warmup 2, after a 500 ms CPU ramp (without the ramp, whichever
  row runs first reads ~50% slower on M-series hosts).
- Sign timing varies the message per iteration: deterministic ML-DSA
  signing re-runs the exact same rejection path for a fixed (key, message),
  so a fixed message would freeze each row on its private luck instead of
  sampling the rejection distribution.
- Sign rows are deterministic where the API offers it (libcrux, RustCrypto,
  fips204 with a fixed hedging seed); PQClean and aws-lc-rs sign hedged —
  one extra 32-byte RNG draw, noise at these costs.
- Same method as the PQShield NIST-sig-zoo, so cycle medians are directly
  comparable. On x86_64 the report adds serialized-rdtsc cycle counts; on
  other hosts it is wall-clock only.

## Other Falcon implementations, not benchmarked here

- **Algorand** ([algorand/falcon](https://github.com/algorand/falcon)) — the
  Falcon reference C with Algorand's deterministic-signing extension; drives
  their AVM `falcon_verify` opcode and State Proofs in production. Same
  padded wire format as the rows above, but there is no Rust crate: adding a
  row means vendoring the C with a build script, which this repo avoids for
  now.
- **Firedancer** ([firedancer-io/firedancer#9446](https://github.com/firedancer-io/firedancer/pull/9446))
  — hand-vectorized AVX-512 verify, ~3.9 µs published, the fastest Falcon
  verify anywhere and the practical performance ceiling. x86-only (cannot
  run on Apple Silicon) and still an open PR; worth revisiting when a
  validator-class x86 host is available for this benchmark.

## Assurance and adoption (ML-DSA rows)

Verified as of 2026-07-07; links are to the primary evidence. Short
version: none of the five has a completed, commissioned third-party audit
of its ML-DSA; the differences are in formal-verification coverage,
certification pipelines, and who depends on them.

**libcrux-ml-dsa (Cryspen).** First-party machine-checked proofs (hax/F*)
cover field arithmetic, NTT and serialization on the portable and AVX2
paths ([crate README](https://github.com/cryspen/libcrux/tree/main/libcrux-ml-dsa));
the high-level signer/verifier logic, including the rejection-sampling
loop, is outside the proved core
([Cryspen on the limits](https://cryspen.com/post/strengths-and-limitations/)).
Two independent 2026 analyses by Symbolic Software dispute the strength of
those claims: [ePrint 2026/192](https://eprint.iacr.org/2026/192) (FIPS 204
violations in the unverified verifier path, an unsound AVX2 proof axiom)
and [ePrint 2026/670](https://eprint.iacr.org/2026/670) (the hax pipeline
extracts unannotated loops as proof-inert). A high-severity AVX2 verify bug
([GHSA-fhvh-vw7h-9xf3](https://github.com/advisories/GHSA-fhvh-vw7h-9xf3),
CVSS 8.2) was fixed in 0.0.9 — the portable path benchmarked here was not
affected. Signal, Mozilla NSS and OpenMLS adopt the libcrux *ML-KEM* and
classical crates; no notable production user of the ML-DSA crate was found
([reverse deps](https://lib.rs/crates/libcrux-ml-dsa/rev)).

**ml-dsa (RustCrypto).** The README states it "has never been independently
audited" ([repo](https://github.com/RustCrypto/signatures/tree/master/ml-dsa)).
Two externally reported issues were fixed pre-0.1.0:
[RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144.html)
(timing side-channel) and GHSA-5x2r-hc65-25f9 (hint-index malleability,
reported by Fireblocks). Adopters:
[Bitwarden's SDK crypto crate](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-crypto/Cargo.toml)
(required dependency),
[ANSSI's MLA archive format](https://github.com/ANSSI-FR/MLA/blob/master/mla/Cargo.toml)
(required), and optionally rPGP and Sequoia-PGP for draft OpenPGP-PQC.

**fips204 (integritychain).** No audit, no CAVP/CMVP certificate; CI
replays the NIST ACVP keyGen/sigGen/sigVer vectors
([tests](https://github.com/integritychain/fips204/blob/main/tests/nist_vectors/mod.rs))
and the README claims source-level constant time (manual review plus
dudect), while labeling the crate experimental. Notable adopter:
[Caliptra](https://github.com/chipsalliance/caliptra-sw/blob/main/image/crypto/Cargo.toml)
(CHIPS Alliance / OCP silicon root of trust) uses it for ML-DSA firmware
image signing, vendored into Meta's openbmc via the Caliptra tooling.

**pqcrypto-mldsa (PQClean C).** No audit; PQClean's SECURITY.md says its
implementations "have not been subjected to rigorous security audits."
Assurance rests on the derivation from the pq-crystals reference code plus
PQClean's sanitizer/Valgrind CI. Note the supply-chain fact: PQClean is
winding down and is slated to be archived read-only in July 2026
([README](https://github.com/PQClean/PQClean)), with maintainers pointing
to the PQ Code Package project. Consumed broadly via the
[pqcrypto crates](https://github.com/rustpq/pqcrypto) and other language
wrappers; libcrux itself uses it as a test oracle. (liboqs sources its
ML-DSA from mldsa-native, not PQClean.)

**aws-lc-rs (AWS-LC).** The strongest assurance story of the five, with a
twist: AWS-LC's ML-DSA is imported from
[mldsa-native](https://github.com/pq-code-package/mldsa-native) (PQ Code
Package / Linux Foundation), which ships machine-checked
[proofs](https://github.com/pq-code-package/mldsa-native/tree/main/proofs):
CBMC absence-of-undefined-behaviour for the C, HOL Light/s2n-bignum
functional-correctness and constant-time proofs for the AArch64 assembly.
AWS-LC holds FIPS 140-3 certificates
([#5298](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298),
[#5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314),
June 2026) whose validated boundary covers ML-KEM but not yet ML-DSA (the
AWS-LC 4 modules are in the CMVP pipeline). Adopters: rustls (aws-lc-rs is
the default provider; ML-DSA signing behind `aws-lc-rs-unstable`), AWS KMS
(ML-DSA-44/65/87 GA) and AWS Private CA
([AWS PQC page](https://aws.amazon.com/security/post-quantum-cryptography/)).
