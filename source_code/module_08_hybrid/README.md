# Module 08: Hybrid Cryptography

## Overview

This module covers hybrid cryptography - combining classical and post-quantum algorithms to maintain security during the transition period. Hybrid schemes ensure security even if one component is compromised.

## Programs

| File | Description | Key Concepts |
|------|-------------|--------------|
| unit_8_2_xwing_test_suite.c | X-Wing KEM tests | X25519 + ML-KEM hybrid |
| unit_8_3_hybrid_signature_test.c | Hybrid signature demo | Ed25519 + ML-DSA-65 |
| unit_8_5_hybrid_crypto_test_suite.c | Test framework | Hybrid library testing patterns |
| unit_8_5_integration_test_suite.c | Integration tests | End-to-end hybrid operations |

## Building

```bash
make
```

## Running Examples

```bash
# Run X-Wing test suite
./unit_8_2_xwing_test_suite

# Run hybrid signature demo
./unit_8_3_hybrid_signature_test

# Run integration tests
./unit_8_5_integration_test_suite
```

## Dependencies

- Standard C library
- For production: OpenSSL, liboqs

## Hybrid Constructions

### X-Wing KEM (Hybrid Key Encapsulation)
- Classical: X25519 (ECDH)
- Post-Quantum: ML-KEM-768
- Combined key: K = H(K_classical || K_pq)

### Hybrid Signatures (Ed25519 + ML-DSA-65)
- Classical: Ed25519 (64 byte signature)
- Post-Quantum: ML-DSA-65 (3309 byte signature)
- Combined: Concatenation (3373 bytes total)

## Key Sizes

| Component | Public Key | Secret Key | Signature/Ciphertext |
|-----------|------------|------------|---------------------|
| Ed25519 | 32 B | 64 B | 64 B |
| ML-DSA-65 | 1952 B | 4032 B | 3309 B |
| Hybrid Sig | 1984 B | 4096 B | 3373 B |
| X25519 | 32 B | 32 B | 32 B |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B |
| X-Wing | 1216 B | 2432 B | 1120 B |
