# Module 02: Mathematical Foundations

## Overview

This module covers the essential mathematical operations used throughout post-quantum cryptography, focusing on modular arithmetic, polynomial rings, and the Number Theoretic Transform (NTT).

## Programs

| File | Description | Key Concepts |
|------|-------------|--------------|
| unit_2_1_mod_basic.c | Basic modular arithmetic | Addition, subtraction, multiplication mod q |
| unit_2_1_mod_exp.c | Modular exponentiation | Fast exponentiation algorithm |
| unit_2_1_gcd_extended.c | Extended GCD | Bezout's identity, modular inverse |
| unit_2_1_fermat_inverse.c | Fermat's little theorem | Computing inverses via a^(p-2) |
| unit_2_1_barrett.c | Barrett reduction | Fast modular reduction without division |
| unit_2_1_test_barrett.c | Barrett exhaustive test | Full range verification |
| unit_2_2_rq_basic.c | Polynomial ring operations | Z_q[X]/(X^256 + 1) |
| unit_2_2_check_inverse.c | Polynomial inverse verification | NTT-domain operations |
| unit_2_2_verify_x256.c | Negacyclic property | X^256 ≡ -1 verification |
| unit_2_3_poly_add_sub.c | Polynomial addition/subtraction | Basic polynomial operations |
| unit_2_3_poly_mul_naive.c | Naive polynomial multiplication | Schoolbook algorithm |
| unit_2_3_poly_infnorm.c | Polynomial infinity norm | Max coefficient magnitude |
| unit_2_3_negacyclic_test.c | Negacyclic reduction | Reduction mod X^N + 1 |
| unit_2_3_compress.c | Compression functions | Lossy encoding for key compression |
| unit_2_3_bitpack.c | Bit packing | Efficient coefficient storage |
| unit_2_4_matvec.c | Matrix-vector operations | A * s + e computation |
| unit_2_4_polyvec_infnorm.c | Vector infinity norm | Component-wise max norm |
| unit_2_5_ntt.c | Number Theoretic Transform | Fast polynomial multiplication |
| unit_2_5_verify_twiddle.c | Twiddle factor verification | NTT precomputation |
| unit_2_6_cbd.c | Centered Binomial Distribution | Error sampling |
| unit_2_6_cbd_empirical.c | CBD empirical analysis | Statistical verification |

## Building

```bash
make
```

## Running Examples

```bash
# Run basic modular arithmetic demo
./unit_2_1_mod_basic

# Run NTT demonstration
./unit_2_5_ntt

# Run CBD distribution analysis
./unit_2_6_cbd_empirical
```

## Dependencies

- Standard C library
- math.h (-lm)

## Key Parameters

- **ML-KEM modulus:** q = 3329
- **ML-DSA modulus:** q = 8380417
- **Polynomial degree:** n = 256
