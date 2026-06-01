# Module 11: Migrating Legacy Codebases - Extracted Programs

This directory contains all 8 C/C++ programs extracted from Module 11 of the PQC Developer's Handbook.

## Programs Overview

### 1. unit_11_1_rsa_toy_example.c
**Topic:** RSA Cryptography Fundamentals (Section 1.1.2)
- Implements toy RSA encryption/decryption with small primes
- Demonstrates modular exponentiation and modular inverse
- Educational example showing RSA vulnerability to quantum attacks
- **Compile:** `gcc -o unit_11_1_rsa_toy_example unit_11_1_rsa_toy_example.c`

### 2. unit_11_2_x25519_key_exchange.c
**Topic:** Elliptic Curve Cryptography (Section 1.1.3)
- X25519 key exchange using OpenSSL
- Demonstrates ECDH protocol between Alice and Bob
- Shows quantum vulnerability of elliptic curves
- **Compile:** `gcc -o unit_11_2_x25519_key_exchange unit_11_2_x25519_key_exchange.c -lssl -lcrypto`

### 3. unit_11_3_sha3_shake_hashing.c
**Topic:** Hash Functions - SHA-3 and SHAKE (Section 1.1.4)
- Demonstrates SHA3-256 hashing
- Shows SHAKE256 extendable output function (XOF)
- Critical foundation for ML-KEM and ML-DSA
- **Compile:** `gcc -o unit_11_3_sha3_shake_hashing unit_11_3_sha3_shake_hashing.c -lssl -lcrypto`

### 4. unit_11_4_lattice_svp_cvp.cpp
**Topic:** Lattice-Based Cryptography Foundations (Section 1.4.1)
- C++ visualization of 2D lattice problems
- Implements Shortest Vector Problem (SVP)
- Implements Closest Vector Problem (CVP)
- Demonstrates hardness assumptions behind PQC
- **Compile:** `g++ -o unit_11_4_lattice_svp_cvp unit_11_4_lattice_svp_cvp.cpp`

### 5. unit_11_5_toy_lwe_encryption.c
**Topic:** Learning With Errors (LWE) - The Foundation (Section 1.4.3)
- Complete toy LWE encryption implementation
- Key generation, encryption, and decryption
- Educational parameters (n=16, m=32, q=97)
- Demonstrates noise-based security
- **Compile:** `gcc -o unit_11_5_toy_lwe_encryption unit_11_5_toy_lwe_encryption.c`

### 6. unit_11_6_lamport_signatures.c
**Topic:** One-Time Signatures - Lamport Scheme (Section 1.5.1)
- Lamport one-time signature implementation
- Hash-based quantum-resistant signatures
- Key generation, signing, and verification
- **Compile:** `gcc -o unit_11_6_lamport_signatures unit_11_6_lamport_signatures.c -lssl -lcrypto`

### 7. unit_11_7_merkle_tree_auth.c
**Topic:** Merkle Trees for Many-Time Signatures (Section 1.5.3)
- Merkle tree construction and verification
- Authentication path generation
- Foundation for SLH-DSA (SPHINCS+)
- **Compile:** `gcc -o unit_11_7_merkle_tree_auth unit_11_7_merkle_tree_auth.c -lssl -lcrypto`

### 8. unit_11_8_timing_test.c
**Topic:** Constant-Time Programming (Section 4.1)
- Framework for testing timing side channels
- Statistical timing analysis with t-test
- Uses RDTSC for high-resolution timing
- **Note:** Requires external `function_under_test()` to compile
- **Compile:** `gcc -o unit_11_8_timing_test unit_11_8_timing_test.c -lm` (with test function)

## Compilation Status

✅ **7 out of 8 programs compile and run successfully**

- Programs 1-7: Compile and execute without errors
- Program 8 (timing_test): Framework only - requires external function to link

## Quick Test

Run all compiled programs:
```bash
./unit_11_1_rsa_toy_example
./unit_11_4_lattice_svp_cvp
./unit_11_5_toy_lwe_encryption
./unit_11_8_timing_test

# Requires OpenSSL:
./unit_11_2_x25519_key_exchange
./unit_11_3_sha3_shake_hashing
./unit_11_6_lamport_signatures
./unit_11_7_merkle_tree_auth
```

## Expected Output

### unit_11_1_rsa_toy_example
```
RSA Toy Example:
p = 61, q = 53
n = 3233
e = 17 (public)
d = 2753 (private)

Original:  123
Encrypted: 855
Decrypted: 123
```

### unit_11_5_toy_lwe_encryption
```
=== Toy LWE Encryption ===
Parameters: n=16, m=32, q=97

Keys generated.
Tested 1000 encryptions
Decryption errors: 0 (0.00%)

--- Detailed Example ---
Original:  1
Decrypted: 1
Status: SUCCESS
```

### unit_11_8_timing_test
```
=== Constant-Time Testing Framework ===
Demonstrating timing analysis with stub function.
Replace function_under_test() with actual crypto code for real testing.

Zero input:   avg = 123.XX cycles, var = XXXXX.XX
Random input: avg = 134.XX cycles, var = XXXXX.XX
Difference:   XX.XX cycles (X.XX%)
t-statistic: X.XX (should be < 2 for constant time)
```
(Values vary by system; t-statistic indicates timing consistency)

## Dependencies

- **gcc/g++:** C/C++ compiler
- **OpenSSL 3.x:** For cryptographic primitives (programs 2, 3, 6, 7)
- **libm:** Math library (program 8)

## Educational Purpose

These programs demonstrate:
1. Classical cryptography vulnerable to quantum attacks (RSA, ECC)
2. Foundations of post-quantum cryptography (lattices, LWE)
3. Hash-based signatures (Lamport, Merkle trees)
4. Cryptographic implementation best practices (constant-time)

## Source

All programs extracted from:
- **File:** pqc-developers-handbook.md
- **Module:** 11 - Migrating Legacy Codebases
- **Line Range:** 51564-53507
