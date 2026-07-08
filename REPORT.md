# PQ Signature Benchmark — Measured Report

> Within each scheme every row verifies the identical (pk, sig) bytes.
> Median of **1000 iterations** for verify (the PQShield-zoo method) and
> **100** for keygen/sign (off-chain context), warmup 2.
> Measurement host: **non-x86 (wall-clock ns; no rdtsc)**.

## 1. Verify cost + footprint

| Scheme | Implementation | pk (B) | sig (B) | pk+sig (B) | keygen | sign | verify | vs Ed25519 |
| --- | --- | --:| --:| --:| --:| --:| --:| --:|
| Ed25519 | fastcrypto (baseline) | 32 | 64 | 96 | 10.4 µs | 11.2 µs | 28.0 µs | 1.00× |
| FN-DSA-512 | Falcon-512 | 897 | 666 | 1563 | n/a | n/a | 13.2 µs | 0.47× |
| FN-DSA-512 | Falcon-512 (PQClean C) | 897 | 666 | 1563 | 4.10 ms | 144.6 µs | 20.4 µs | 0.73× |
| ML-DSA-44 | libcrux | 1312 | 2420 | 3732 | 36.6 µs | 107.0 µs | 35.6 µs | 1.27× |
| ML-DSA-44 | RustCrypto ml-dsa | 1312 | 2420 | 3732 | 79.6 µs | 140.5 µs | 24.1 µs | 0.86× |
| ML-DSA-44 | fips204 | 1312 | 2420 | 3732 | 77.8 µs | 168.6 µs | 54.2 µs | 1.94× |
| ML-DSA-44 | PQClean C | 1312 | 2420 | 3732 | 21.3 µs | 49.1 µs | 20.2 µs | 0.72× |
| ML-DSA-44 | aws-lc-rs | 1312 | 2420 | 3732 | 17.9 µs | 37.0 µs | 14.4 µs | 0.52× |
