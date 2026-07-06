# pq-sig-bench

Verify-cost benchmarks for the post-quantum signature work in
[mahdi-mysten/fastcrypto (`pq-schemes`)](https://github.com/mahdi-mysten/fastcrypto/tree/pq-schemes).
Falcon-512 only for now: fastcrypto's Montgomery-NTT verifier against
PQClean's reference C (`pqcrypto-falcon`), both timing the identical
signature bytes. Rows for the other schemes get added as their fastcrypto
modules land.

## Run

```
cargo run --release --bin report
```

Prints the report and writes `REPORT.md` and `results.csv` into the repo
root. Takes a few seconds; most of it is the PQClean keygen samples.

## Method

Median of 1000 iterations for verify and 100 for keygen/sign, fixed counts,
warmup 2 — the same method as the PQShield NIST-sig-zoo, so cycle medians
are directly comparable. On x86_64 the report adds serialized-rdtsc cycle
counts; on other hosts it is wall-clock only. Every row passes a
sign→verify/tamper self-check (including PQClean→fastcrypto cross-
verification) before its timing is trusted.

The fastcrypto dependency tracks the `pq-schemes` branch; run
`cargo update -p fastcrypto` to pick up new pushes.
