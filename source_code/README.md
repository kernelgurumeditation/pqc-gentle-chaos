# PQC Developer's Handbook - Source Code Examples

This directory contains all compilable C source code examples from the Post-Quantum Cryptography Developer's Handbook.

## Directory Structure

```
source_code/
├── Makefile                    # Master Makefile
├── README.md                   # This file
├── common/                     # Shared utilities and headers
├── module_02_math_foundations/ # Mathematical foundations
├── module_03_lattice_theory/   # Lattice cryptography theory
├── module_04_ml_kem/           # ML-KEM deep dive
├── module_05_signatures_theory/# Digital signatures theory
├── module_06_ml_dsa/           # ML-DSA implementation
├── module_07_slh_dsa/          # SLH-DSA/hash-based signatures
├── module_08_hybrid/           # Hybrid cryptography
├── module_09_protocols/        # Protocol integration
├── module_10_future/           # Future algorithms
└── module_11_migration/        # Migration examples
```

## Building

### Prerequisites

- GCC or Clang compiler
- Make
- Standard C library

### Build All Examples

```bash
make
```

### Build Specific Module

```bash
make module_02_math_foundations
```

### Clean Build Artifacts

```bash
make clean
```

### Run Tests

```bash
make test
# or directly:
./run_tests.sh
```

The test runner validates that all programs compile and produce expected output patterns.

## Module Contents

### Module 2: Mathematical Foundations
- Modular arithmetic operations
- Extended Euclidean algorithm
- Barrett and Montgomery reduction
- Polynomial ring arithmetic
- Number Theoretic Transform (NTT)
- Probability distributions and sampling

### Module 3: Lattice Cryptography Theory
- Lattice basics and hard problems
- LWE (Learning With Errors) examples
- Ring-LWE and Module-LWE structures
- Basic public key encryption from LWE

### Module 4: ML-KEM Deep Dive
- KEM security concepts
- K-PKE encryption scheme
- Fujisaki-Okamoto transform

### Module 5: Digital Signatures Theory
- Signature security demonstrations
- Fiat-Shamir transform
- Schnorr signatures
- Lattice signature overview

### Module 6: ML-DSA Deep Dive
- ML-DSA structure and parameters
- Rejection sampling
- Key generation, signing, verification
- Complete ML-DSA implementation

### Module 7: SLH-DSA (Hash-Based Signatures)
- Lamport one-time signatures
- Merkle trees
- WOTS+ implementation
- XMSS and hypertrees
- FORS construction
- Complete SLH-DSA implementation

### Module 8: Hybrid Cryptography
- X-Wing hybrid KEM
- Hybrid signatures
- Composite key formats

### Module 9-11: Protocols, Future, Migration
- Protocol integration examples
- Cryptographic agility
- Migration patterns

## Notes

- These are educational implementations for learning purposes
- Not intended for production use
- Some examples are simplified for clarity
- Full implementations should use vetted libraries like liboqs

## License

These code examples accompany the PQC Developer's Handbook.
