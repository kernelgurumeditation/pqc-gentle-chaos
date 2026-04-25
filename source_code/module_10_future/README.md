# Module 10: Future Algorithms — Source Code

Companion code for Handbook Module 10: FALCON, BIKE, HQC, threshold cryptography, cryptographic agility.

## Files

| File | Purpose | External deps |
|------|---------|---------------|
| `unit_10_1_crypto_agility.c` | Algorithm registry + runtime selection pattern | none |
| `unit_10_2_falcon_wrapper.c` | FALCON / FN-DSA sign/verify demo via liboqs | liboqs |
| `unit_10_3_hqc_demo.c` | HQC KEM demo (with prominent CVE warnings) | liboqs |
| `unit_10_4_bike_demo.c` | BIKE KEM demo (research candidate) | liboqs |

## Build

```bash
# Framework-only demos (no external deps)
make self-contained
make test

# liboqs-backed algorithm demos
make liboqs
```

## Important Notes

- **FIPS 206 (FN-DSA/FALCON)** is an Initial Public Draft (August 2025); not yet a finalized standard. Final expected late 2026 or 2027.
- **HQC** is disabled by default in liboqs 0.13+ due to three CVEs (see Handbook Unit 11.10). Do NOT use in production as of April 2026.
- **BIKE** was not selected by NIST; included for algorithm-diversity experimentation only.
- Threshold PQC (Hermine, Quorus, Vinaigrette) has no production-ready implementation as of April 2026 — see Handbook Unit 10.6.

## Cross-references

- Handbook Unit 10.1 — NIST additional algorithms
- Handbook Unit 10.3 — Cryptographic agility architecture
- Handbook Unit 10.5 — NIST Round 2 signatures
- Handbook Unit 10.6 — Threshold PQC
- Handbook Unit 11.10 — CVE registry (HQC bug history)
