# Post-quantum signature benchmarks

Timing benchmarks for the post-quantum signature schemes we are adding to
[fastcrypto](https://github.com/MystenLabs/fastcrypto). One command runs
everything:

```
cargo run --release --bin report
```

It prints the report and writes `REPORT.md` and `results.csv` to the repo
root. The report has two sections.

Section 1, "Verify cost + footprint", compares schemes. How expensive is
each one to verify compared to the Ed25519 verification Sui runs today,
and what do the parameter sets cost relative to each other, measured the
same way on the same machine? For each row it prints the public key and
signature sizes, the median keygen, sign, and verify times, and the
verify cost as a ratio of Ed25519.

The scheme decision is made: ML-DSA-65, security category 3. The trait
layer lives in fastcrypto's `fastcrypto-pq` crate. The question that
remained was which implementation to run, and section 2, "ML-DSA-65
implementation options", answers it: our wrapper against every way a Rust
project can get ML-DSA-65 today. Each contender is cross-verified against
the wrapper before it is timed, and each cell in its table is the
contender's median plus the signed difference from the wrapper's own row
in section 1.

## What is measured (section 1)

One implementation is benchmarked per row: the one we would actually run.
Correctness is still gated before anything is timed: every row has to
verify a signature it produced and reject a tampered copy, and the
SLH-DSA row additionally roundtrips its signature through the FIPS 205
byte encoding so the size column reports a real wire format.

Ed25519 is the baseline, measured through fastcrypto itself, because that
is what a Sui validator runs today. One caveat: validators batch Ed25519
verifications, which roughly halves the amortized cost, and no PQ scheme
can be batched. The "vs Ed25519" ratios in the report therefore understate
the real gap by about 2x.

FN-DSA-512 and FN-DSA-1024 (Falcon) are both measured on PQClean's
portable C (`falcon-padded-512` / `falcon-padded-1024`, via the
[`pqcrypto-falcon`](https://github.com/rustpq/pqcrypto) bindings), in the
padded fixed-size signature format, built without SIMD (no NEON/AVX2) to
match the configuration fastcrypto ships. Earlier revisions measured
FN-DSA-512 through fastcrypto's falcon512 module on the
`mahdi/fn-dsa-512` branch, whose strict verifier also re-checks every
signature inside sign; the dependency now tracks the sphincs branch for
the SLH-DSA row, and that branch carries no falcon module, so the
FN-DSA-512 numbers are the raw C without that gate and read a little
faster than the old fastcrypto row did.

SLH-DSA-SHA2-128s is measured through fastcrypto's sphincs module (pure
Rust, behind the `experimental` feature): the stateless hash-based
scheme, whose security reduces to SHA-256 with no lattice assumption.
The 128s parameter set is the small-signature/slow-sign end of the
trade, which is the relevant end when the signature is what gets stored
and verified on chain. Signing still costs hundreds of milliseconds,
which is what the timer's adaptive iteration count exists for.

ML-DSA is measured through our
[mysten-mldsa-native-rs](https://github.com/MystenLabs/mysten-mldsa-native-rs)
wrapper at all three security levels, 44, 65, and 87, with the wrapper's
`native` feature on (NEON + SHA3 kernels on aarch64, AVX2 on x86_64; the
default `mysten-native` feature of this crate enables it, and the row
label in the report records which backend was measured). The wrapper
consumes the same mldsa-native C that AWS-LC imports, without the
libcrypto build around it. The ML-DSA-65 row is flagged as our pick in
the report, and section 2 measures everything against it.

## The ML-DSA-65 contenders (section 2)

The code is in `src/schemes/mldsa_options.rs`. Four contenders, and why
each is there.

aws-lc-rs wraps the same verified mldsa-native C we do, so this pair
isolates what the integration costs: aws-lc goes through its libcrypto
build and EVP layer, the wrapper through a single-TU build and direct
FFI. It is also what NEAR's nearcore uses for its mainnet ML-DSA-65
accounts (`core/crypto/Cargo.toml` depends on aws-lc-rs), so the row
doubles as a read on how our numbers compare with NEAR's, minus their
protocol overhead.

ml-dsa is RustCrypto's pure Rust implementation. libcrux-ml-dsa is
Cryspen's formally verified crate; as released its SIMD path targets
AVX2, so on an aarch64 machine it runs its portable code, which is what a
consumer gets today. pqcrypto-mldsa is PQClean's portable reference C,
from the same bindings family as the FN-DSA-1024 row.

Every contender must accept a signature from the wrapper and produce one
the wrapper accepts before its timing starts; the aws-lc-rs gate also
checks that a tampered message is rejected. A contender that fails the
gate aborts the run.

The measured numbers live in `REPORT.md`, not here, because they
regenerate on every run. The shape has been stable: aws-lc-rs is the
closest, within a few percent of the wrapper on verify and 5-15% behind
on keygen and sign, and the pure Rust and reference C options run from
roughly 20% to several times slower depending on the operation. Together with the binary footprint measured in a separate
harness (the wrapper with native backends adds ~85 KB to a release
binary, aws-lc-rs adds ~1.7 MB), that is the case for shipping the
wrapper rather than taking a library.

## How to run it

```
cargo run --release --bin report
```

You need a Rust toolchain and cmake (`brew install cmake`). The first
build compiles AWS-LC from source and takes a few minutes. After that a
full run takes about 40 seconds, most of it the SLH-DSA signing
measurement (30 iterations of a ~0.8 s operation).

`REPORT.md` is the rendered report. `results.csv` holds the same data,
one row per measurement: the scheme rows first, with sizes and the
Ed25519 ratio, then the section 2 contenders, which leave the size
columns empty because those belong to the scheme rows above.

The fastcrypto dependency tracks the `feat/slh-dsa-toplevel` branch of
[mahdi-mysten/fastcrypto](https://github.com/mahdi-mysten/fastcrypto),
which carries the top-level FIPS 205 sign/verify and the NIST ACVP KATs
that upstream main's sphincs building blocks still lack. Run
`cargo update -p fastcrypto` after a new push there. The wrapper
dependency tracks mysten-mldsa-native-rs's `mahdi/multilevel-v2` branch,
where the ML-DSA-44/87 feature gates live; point it at a local path in
`Cargo.toml` to bench a working tree instead.

## How the timing works

Every number is a median over 1000 iterations, with 2 warmup rounds per
measurement. An operation whose one-call probe exceeds 1 ms gets
proportionally fewer iterations (floor 30) so one measurement costs about
a second instead of stretching the run by 1000x the op time; the actual
per-row counts are printed in the report's `iters` column, and p10/p90
land in `results.csv` so the spread around each median is visible.

The benchmark thread is pinned before anything runs: `sched_setaffinity`
to a single nonzero CPU on Linux, and QoS `USER_INTERACTIVE` on macOS,
which has no core-pinning API but this keeps the thread off the
efficiency cores that cause most run-to-run drift on Apple Silicon.

The wall clock is `std::time::Instant`, which reads
`clock_gettime(CLOCK_MONOTONIC)` on Linux and the mach monotonic clock on
macOS. On x86_64 Linux the report also records real core cycles: a
per-thread `perf_event_open(PERF_COUNT_HW_CPU_CYCLES, exclude_kernel)`
counter read from user space with `rdpmc` under the perf page's seqlock
protocol. Apple Silicon has no user-space cycle counter, so on this
machine the report is wall-clock only, and the method preamble in
`REPORT.md` is generated from what the run actually did on its host.

Two details matter more than they look:

1. The CPU is warmed up with a 500 ms busy loop before anything is timed.
   Without it, whichever row happens to run first reads about 50% slower
   on M-series machines, because the core has not reached its sustained
   frequency yet.
2. Sign timing uses a different message on every iteration. Falcon and
   ML-DSA signing run rejection loops whose length depends on the exact
   inputs. Most of the benchmarked signers are randomized (fastcrypto's
   Falcon draws its salt from the OS; the wrapper and aws-lc-rs sign
   hedged), which already varies the path per call. The RustCrypto
   contender signs deterministically, so for it the varying message is
   the only source of fresh rejection paths.

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

## Audits, and who actually uses these (ML-DSA implementations)

Section 2 benchmarks four of the five implementations written up below;
fips204 is the one without a row. The write-ups are kept for all five
because the audit and adoption picture carries as much weight as the
timings.

| Implementation | What it is |
| --- | --- |
| [libcrux](https://github.com/cryspen/libcrux/tree/main/libcrux-ml-dsa) | Cryspen's crate, portable code path. |
| [RustCrypto ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) | Pure Rust, from the RustCrypto signatures repo. |
| [fips204](https://github.com/integritychain/fips204) | Pure Rust, by integritychain. |
| [PQClean C](https://github.com/PQClean/PQClean) | The C reference code, via the [`pqcrypto-mldsa`](https://github.com/rustpq/pqcrypto) bindings. |
| [aws-lc-rs](https://github.com/aws/aws-lc-rs) | AWS-LC's C implementation, behind the crate's `unstable` feature. |

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
The portable path we benchmarked was not affected.

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

The wrapper we benchmark against consumes that same mldsa-native C
directly, so the assurance story in this last write-up is also ours; what
section 2 measures is the cost of the packaging around it.
