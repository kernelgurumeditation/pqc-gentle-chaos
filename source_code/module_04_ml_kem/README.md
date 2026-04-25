# Module 04: ML-KEM (Key Encapsulation Mechanism)

## Overview

This module covers ML-KEM (Module-Lattice Key Encapsulation Mechanism), the NIST-standardized post-quantum key encapsulation scheme based on the Module-LWE problem. ML-KEM is the successor to CRYSTALS-Kyber.

## Programs

| File | Description | Key Concepts |
|------|-------------|--------------|
| unit_4_1_kem_concepts.c | KEM fundamentals | Encapsulation vs encryption, shared secrets |
| unit_4_2_kpke.c | K-PKE construction | Underlying public key encryption |
| unit_4_3_fo_transform.c | Fujisaki-Okamoto transform | CCA security from CPA security |

## Building

```bash
make
```

## Running Examples

```bash
# Run KEM concepts demonstration
./unit_4_1_kem_concepts

# Run K-PKE encryption/decryption
./unit_4_2_kpke

# Run FO transform demonstration
./unit_4_3_fo_transform
```

## Dependencies

- Standard C library
- math.h (-lm)

## Key Parameters (ML-KEM-768)

| Parameter | Value | Description |
|-----------|-------|-------------|
| n | 256 | Polynomial degree |
| k | 3 | Module dimension |
| q | 3329 | Modulus |
| η₁ | 2 | Secret noise parameter |
| η₂ | 2 | Encryption noise parameter |
| d_u | 10 | Ciphertext compression (u) |
| d_v | 4 | Ciphertext compression (v) |

## Security Levels

| Variant | Security | Public Key | Ciphertext |
|---------|----------|------------|------------|
| ML-KEM-512 | ~128 bits | 800 bytes | 768 bytes |
| ML-KEM-768 | ~192 bits | 1184 bytes | 1088 bytes |
| ML-KEM-1024 | ~256 bits | 1568 bytes | 1568 bytes |
