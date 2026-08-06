# PQ Signature Benchmark - Measured Report

> One implementation per row; each passes a sign→verify + tamper self-check
> before timing.
>
> **Method.** Operations are timed one at a time on a warmed, pinned thread.
> Each number is the median of **1000 iterations**; an op whose one-call
> probe exceeds 1 ms gets proportionally fewer (floor 30) so a
> measurement stays near 1 s - the `iters` column records the actual
> keygen/sign/verify counts per row. p10/p90 for every op are in `results.csv`.
> - Wall clock: mach monotonic clock via std::time::Instant (macOS's CLOCK_MONOTONIC equivalent).
> - Cycle counter: none - Apple Silicon has no user-space cycle counter; wall clock only (on x86_64 Linux this report reads rdpmc CPU_CYCLES).
> - Thread pinning: QoS USER_INTERACTIVE (macOS has no core pinning; this keeps the thread on performance cores).
> - Warmup: 500 ms CPU ramp before any measurement, then 2 untimed
>   iterations per op.
> - Host: aarch64 macos.

## 1. Verify cost + footprint

| Scheme | Implementation | pk (B) | sig (B) | pk+sig (B) | keygen | sign | verify | vs Ed25519 | iters (kg/sign/vf) |
| --- | --- | --:| --:| --:| --:| --:| --:| --:| --:|
| Ed25519 | fastcrypto (baseline) | 32 | 64 | 96 | 10.4 µs | 11.2 µs | 27.9 µs | 1.00× | 1000/1000/1000 |
| FN-DSA-512 | PQClean C | 897 | 666 | 1563 | 8.51 ms | 2.72 ms | 24.9 µs | 0.89× | 132/370/1000 |
| FN-DSA-1024 | PQClean C | 1793 | 1280 | 3073 | 24.34 ms | 5.90 ms | 49.9 µs | 1.79× | 35/169/1000 |
| SLH-DSA-SHA2-128s | fastcrypto sphincs | 32 | 7856 | 7888 | 103.27 ms | 786.77 ms | 774.6 µs | 27.75× | 30/30/1000 |
| ML-DSA-44 | mysten wrapper (native) | 1312 | 2420 | 3732 | 15.0 µs | 33.2 µs | 13.6 µs | 0.49× | 1000/1000/1000 |
| **ML-DSA-65** (our pick) | mysten wrapper (native) | 1952 | 3309 | 5261 | 25.5 µs | 54.2 µs | 23.1 µs | 0.83× | 1000/1000/1000 |
| ML-DSA-87 | mysten wrapper (native) | 2592 | 4627 | 7219 | 40.5 µs | 70.5 µs | 37.7 µs | 1.35× | 1000/1000/1000 |

## 2. ML-DSA-65 implementation options

Percentages are relative to the ML-DSA-65 pick (mysten wrapper (native)) in the table above.

| Implementation | keygen | sign | verify | iters (kg/sign/vf) |
| --- | --:| --:| --:| --:|
| aws-lc-rs (NEAR pick) | 28.5 µs (+12%) | 60.0 µs (+11%) | 24.1 µs (+4%) | 1000/1000/1000 |
| ml-dsa (RustCrypto) | 134.5 µs (+427%) | 249.0 µs (+359%) | 33.4 µs (+45%) | 1000/1000/1000 |
| libcrux-ml-dsa | 60.3 µs (+136%) | 156.2 µs (+188%) | 47.1 µs (+104%) | 1000/1000/1000 |
| pqcrypto-mldsa (PQClean) | 43.6 µs (+71%) | 81.6 µs (+50%) | 29.6 µs (+28%) | 1000/1000/1000 |
