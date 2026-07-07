# Post-quantum signature benchmarks

Timing benchmarks for the post-quantum signature schemes we are adding to
[fastcrypto on the `pq-schemes` branch](https://github.com/mahdi-mysten/fastcrypto/tree/pq-schemes).

The report answers two questions. How expensive is each scheme to verify
compared to the Ed25519 verification Sui runs today? And within one
scheme, how does our implementation compare to the alternatives? For each
row it prints the public key and signature sizes, the median keygen, sign,
and verify times, and the verify cost as a ratio of Ed25519.

The comparison stays fair because a signature scheme's byte format is
fixed by its standard. For each scheme, one key pair and one signature are
generated once, and every implementation verifies those exact bytes. Any
timing difference is the implementation, not the input. Before anything is
timed, each implementation has to verify the shared signature and reject a
tampered copy of it. Implementations that can also sign must produce
signatures the others accept.

## What is measured

Ed25519 is the baseline, measured through fastcrypto itself, because that
is what a Sui validator runs today. One caveat: validators batch Ed25519
verifications, which roughly halves the amortized cost, and no PQ scheme
can be batched. The "vs Ed25519" ratios in the report therefore understate
the real gap by about 2x.

FN-DSA-512 (Falcon) has two rows: fastcrypto's verifier and PQClean's
reference C via `pqcrypto-falcon`. The fastcrypto row reports verify only.
Its keygen and sign are wip, so those cells read n/a and the PQClean row
carries the signing costs.

ML-DSA-44 has five rows, one per implementation:

| Row | What it is |
| --- | --- |
| [libcrux](https://github.com/cryspen/libcrux/tree/main/libcrux-ml-dsa) | Cryspen's crate, portable code path. |
| [RustCrypto ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) | Pure Rust, from the RustCrypto signatures repo. |
| [fips204](https://github.com/integritychain/fips204) | Pure Rust, by integritychain. |
| [PQClean C](https://github.com/PQClean/PQClean) | The C reference code, via the [`pqcrypto-mldsa`](https://github.com/rustpq/pqcrypto) bindings. |
| [aws-lc-rs](https://github.com/aws/aws-lc-rs) | AWS-LC's C implementation, behind the crate's `unstable` feature. |

## How to run it

```
cargo run --release --bin report
```

You need a Rust toolchain and cmake (`brew install cmake`). The first
build compiles AWS-LC from source and takes a few minutes. After that, a
full run takes a few seconds. It prints the report and writes `REPORT.md`
and `results.csv` to the repo root.

The fastcrypto dependency tracks the `pq-schemes` branch of [this fork](https://github.com/mahdi-mysten/fastcrypto). Run
`cargo update -p fastcrypto` after a new push there.

## How the timing works

Every number is a median over a fixed iteration count: 1000 for verify,
100 for keygen and sign, with 2 warmup rounds. This is the same method as
PQShield's NIST-sigs-zoo, so the cycle counts are directly comparable with
the zoo on x86 hosts. Apple Silicon has no rdtsc, so on this machine the
report is wall-clock only.

Two details matter more than they look:

1. The CPU is warmed up with a 500 ms busy loop before anything is timed.
   Without it, whichever row happens to run first reads about 50% slower
   on M-series machines, because the core has not reached its sustained
   frequency yet.
2. Sign timing uses a different message on every iteration. Deterministic
   ML-DSA signing runs a rejection loop whose length depends on the exact
   key and message. With a fixed message, each row would keep re-timing
   the one lucky or unlucky path its inputs happen to hit. Varying the
   message samples the real distribution.

Where an API offers deterministic signing, the benchmark uses it: libcrux,
RustCrypto, and fips204 with a fixed hedging seed. PQClean and aws-lc-rs
only sign hedged, which adds one 32-byte RNG draw per signature. At these
costs that is noise.

## Falcon implementations we know about but do not bench

Algorand maintains a fork of the Falcon reference C with deterministic
signing added ([algorand/falcon](https://github.com/algorand/falcon)). It
runs in production behind their AVM `falcon_verify` opcode and their State
Proofs, and it speaks the same padded signature format as our rows. There
is no Rust crate for it, though. A row would mean vendoring the C with a
build script, and I want to keep this repo on plain crates for now.

Firedancer has a hand-vectorized AVX-512 verifier at a published ~3.9 µs
([firedancer-io/firedancer#9446](https://github.com/firedancer-io/firedancer/pull/9446)).
That is the fastest Falcon verify anywhere and a useful ceiling to keep in
mind. It cannot run on Apple Silicon and the PR is still open, so it waits
until a validator-class x86 host is available for this benchmark.

## Audits, and who actually uses these (ML-DSA rows)

I checked each implementation for two things: has anyone independently
audited it, and does anyone serious depend on it. All claims were checked
on 2026-07-07 and the links go to the primary evidence.

The short answer on audits: none of the five has a completed, commissioned
third-party audit of its ML-DSA. What separates them is how much formal
verification they carry and who has adopted them.

### libcrux

Cryspen's own machine-checked proofs (hax/F*) cover the field arithmetic,
the NTT, and serialization, on both the portable and AVX2 paths
([crate README](https://github.com/cryspen/libcrux/tree/main/libcrux-ml-dsa)).
The higher-level signer and verifier logic, including the
rejection-sampling loop, is outside the proved core. Cryspen says so
themselves ([on the limits](https://cryspen.com/post/strengths-and-limitations/)).

Two 2026 papers from Symbolic Software attack exactly that gap.
[ePrint 2026/192](https://eprint.iacr.org/2026/192) reports FIPS 204
violations in the unverified verifier path and an unsound proof axiom in
the AVX2 code. [ePrint 2026/670](https://eprint.iacr.org/2026/670) shows
the hax pipeline extracting unannotated loops in a way that leaves them
outside the proofs. There was also a high-severity bug in the AVX2
verifier, CVSS 8.2, fixed in 0.0.9
([GHSA-fhvh-vw7h-9xf3](https://github.com/advisories/GHSA-fhvh-vw7h-9xf3)).
The portable path we benchmark was not affected.

On adoption: Signal, Mozilla NSS, and OpenMLS all ship libcrux code, but
the ML-KEM and classical crates. I could not find a notable production
user of the ML-DSA crate
([reverse deps](https://lib.rs/crates/libcrux-ml-dsa/rev)).

### RustCrypto ml-dsa

Its README says it plainly: the crate "has never been independently
audited" ([repo](https://github.com/RustCrypto/signatures/tree/master/ml-dsa)).
Two externally reported issues were fixed before 0.1.0: a timing
side-channel ([RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144.html))
and a hint-index malleability found by Fireblocks (GHSA-5x2r-hc65-25f9).

Adoption is the surprise here. Bitwarden's SDK crypto crate depends on it
unconditionally
([Cargo.toml](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-crypto/Cargo.toml)),
and so does MLA, the archive format from ANSSI, the French cybersecurity
agency ([Cargo.toml](https://github.com/ANSSI-FR/MLA/blob/master/mla/Cargo.toml)).
rPGP and Sequoia-PGP use it optionally for the draft OpenPGP PQC profile.

### fips204

No audit and no CAVP/CMVP certificate. Its CI replays the NIST ACVP
keyGen, sigGen, and sigVer vectors
([tests](https://github.com/integritychain/fips204/blob/main/tests/nist_vectors/mod.rs)).
The README claims source-level constant time based on manual review plus
dudect measurements, and labels the crate experimental.

On adoption: Caliptra, the CHIPS Alliance / OCP silicon root of trust,
uses it to sign firmware images
([Cargo.toml](https://github.com/chipsalliance/caliptra-sw/blob/main/image/crypto/Cargo.toml)).
Meta's openbmc vendors that same tooling.

### PQClean

No audit here either, and its SECURITY.md says the implementations "have
not been subjected to rigorous security audits." What it has instead is
its lineage, since the code derives from the pq-crystals reference, and a
CI that runs sanitizers and Valgrind.

PQClean is also winding down: the repo is slated to be archived
read-only in July 2026 ([README](https://github.com/PQClean/PQClean)),
and the maintainers point users to the PQ Code Package project. It is consumed everywhere through language wrappers,
in Rust via the [pqcrypto crates](https://github.com/rustpq/pqcrypto).
Even libcrux uses it as a test oracle. liboqs, by the way, takes its
ML-DSA from mldsa-native, not from PQClean.

### aws-lc-rs

The strongest assurance story of the five, with a twist: AWS-LC does not
implement ML-DSA itself. It imports
[mldsa-native](https://github.com/pq-code-package/mldsa-native), the PQ
Code Package / Linux Foundation implementation, which ships machine-checked
[proofs](https://github.com/pq-code-package/mldsa-native/tree/main/proofs):
CBMC proofs that the C has no undefined behaviour, and HOL Light proofs,
via s2n-bignum, of functional correctness and constant time for the
AArch64 assembly.

AWS-LC holds FIPS 140-3 certificates
([#5298](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298),
[#5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314),
June 2026), but their validated boundary covers ML-KEM only. ML-DSA is in
the CMVP pipeline with the AWS-LC 4 modules.

On adoption: rustls ships aws-lc-rs as its default crypto provider, with
ML-DSA signing behind the `aws-lc-rs-unstable` feature. AWS KMS offers
ML-DSA-44/65/87 keys in production, and AWS Private CA supports ML-DSA
roots ([AWS PQC page](https://aws.amazon.com/security/post-quantum-cryptography/)).
