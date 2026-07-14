# PQ Signature Benchmark — Measured Report

> One implementation per row; each passes a sign→verify + tamper self-check
> before timing (FN-DSA-512 also cross-verifies with PQClean C, both ways).
> Median of **1000 iterations** for verify (the PQShield-zoo method) and
> **100** for keygen/sign (off-chain context), warmup 2.
> Measurement host: **non-x86 (wall-clock ns; no rdtsc)**.

## 1. Verify cost + footprint

| Scheme | Implementation | pk (B) | sig (B) | pk+sig (B) | keygen | sign | verify | vs Ed25519 |
| --- | --- | --:| --:| --:| --:| --:| --:| --:|
| Ed25519 | fastcrypto (baseline) | 32 | 64 | 96 | 10.4 µs | 11.2 µs | 27.9 µs | 1.00× |
| FN-DSA-512 | fastcrypto | 897 | 666 | 1563 | 8.33 ms | 2.75 ms | 13.2 µs | 0.47× |
| FN-DSA-1024 | PQClean C | 1793 | 1280 | 3073 | 26.25 ms | 5.93 ms | 50.0 µs | 1.79× |
| ML-DSA-44 | aws-lc-rs | 1312 | 2420 | 3732 | 18.0 µs | 46.7 µs | 14.5 µs | 0.52× |
| ML-DSA-65 | aws-lc-rs | 1952 | 3309 | 5261 | 28.7 µs | 66.6 µs | 24.3 µs | 0.87× |
| ML-DSA-87 | aws-lc-rs | 2592 | 4627 | 7219 | 45.0 µs | 84.5 µs | 39.7 µs | 1.42× |
