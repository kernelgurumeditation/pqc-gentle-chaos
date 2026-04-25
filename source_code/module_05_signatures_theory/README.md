# Module 05: Digital Signatures Theory

## Overview

This module covers the theoretical foundations of digital signatures in the post-quantum setting, including security definitions, the Fiat-Shamir transform, and lattice-based signature concepts.

## Programs

| File | Description | Key Concepts |
|------|-------------|--------------|
| unit_5_1_signature_security.c | Signature security models | EUF-CMA, SUF-CMA definitions |
| unit_5_2_fiat_shamir.c | Fiat-Shamir heuristic | Interactive to non-interactive conversion |
| unit_5_3_lattice_signatures.c | Lattice signature concepts | SIS problem, rejection sampling |

## Building

```bash
make
```

## Running Examples

```bash
# Run signature security demo
./unit_5_1_signature_security

# Run Fiat-Shamir demonstration
./unit_5_2_fiat_shamir

# Run lattice signatures overview
./unit_5_3_lattice_signatures
```

## Dependencies

- Standard C library
- math.h (-lm)

## Key Concepts

### Security Models

- **EUF-CMA:** Existential Unforgeability under Chosen Message Attack
- **SUF-CMA:** Strong Unforgeability under Chosen Message Attack

### Fiat-Shamir Transform

Converts a sigma protocol (3-round interactive proof) into a non-interactive signature:
1. Commitment → (computed by signer)
2. Challenge → H(commitment || message)
3. Response → (computed using secret key)

### Lattice Signatures

Based on the Short Integer Solution (SIS) problem:
- Given random matrix A, find short vector z such that Az = 0
- Security relies on hardness of finding short vectors in lattices
