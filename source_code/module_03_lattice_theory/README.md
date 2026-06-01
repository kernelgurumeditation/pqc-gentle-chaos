# Module 3: Lattice Cryptography Theory - C Programs

This directory contains all C programs extracted from Module 3 of the PQC Developer's Handbook.

## Extracted Programs

### Unit 3.1: Lattices and Hard Problems

**`unit_3_1_lattice_basics.c`**
- **Source**: Lines 4860-5036 of pqc-developers-handbook.md
- **Description**: Basic lattice operations for educational purposes
- **Features**:
  - Lattice point generation from basis vectors
  - Shortest Vector Problem (SVP) via naive enumeration
  - Closest Vector Problem (CVP) via rounding heuristic
  - Lattice determinant computation
- **Compilation**: `gcc -Wall -o unit_3_1_lattice_basics unit_3_1_lattice_basics.c -lm`

### Unit 3.2: Learning With Errors (LWE)

**`unit_3_2_lwe_basics.c`**
- **Source**: Lines 5576-5739 of pqc-developers-handbook.md
- **Description**: Educational LWE implementation
- **Features**:
  - LWE key generation (public/secret key pairs)
  - Regev encryption scheme (encrypt single bits)
  - LWE decryption with error tolerance
  - Decryption failure rate testing
- **Compilation**: `gcc -Wall -o unit_3_2_lwe_basics unit_3_2_lwe_basics.c`

**`unit_3_2_brute_force_lwe.c`**
- **Source**: Lines 5937-6028 of pqc-developers-handbook.md (Exercise 3.2.7)
- **Description**: Brute force attack on small LWE instances
- **Features**:
  - Exhaustive search over all possible secrets
  - Complexity analysis (O(q^n) operations)
  - Demonstrates why LWE is secure for cryptographic parameters
- **Compilation**: `gcc -Wall -o unit_3_2_brute_force_lwe unit_3_2_brute_force_lwe.c`
- **Note**: For n=2, q=17, requires 289 attempts (feasible). For n=256, q=3329, requires 3329^256 ≈ 2^3000 attempts (infeasible!)

### Unit 3.3: Ring-LWE and Module-LWE

**`unit_3_3_module_lwe.c`**
- **Source**: Lines 6333-6501 of pqc-developers-handbook.md
- **Description**: Module-LWE data structures and operations
- **Features**:
  - Polynomial and polynomial vector operations
  - Module-LWE key generation structure
  - Matrix-vector multiplication over polynomial rings
  - Key size analysis for ML-KEM-768-like parameters
- **Compilation**: `gcc -Wall -o unit_3_3_module_lwe unit_3_3_module_lwe.c`
- **Note**: Real implementations use NTT for efficient polynomial multiplication

**`unit_3_3_anticirculant_demo.c`**
- **Source**: Lines 6711-6838 of pqc-developers-handbook.md (Exercise 3.3.7)
- **Description**: Verify polynomial multiplication equals matrix multiplication
- **Features**:
  - Building anti-circulant matrix from polynomial coefficients
  - Polynomial multiplication in Zq[X]/(X^4+1)
  - Equivalence demonstration between polynomial and matrix operations
  - Negacyclic structure (X^n ≡ -1)
- **Compilation**: `gcc -Wall -o unit_3_3_anticirculant_demo unit_3_3_anticirculant_demo.c`

### Unit 3.4: From LWE to Public Key Encryption

**`unit_3_4_kpke.c`**
- **Source**: Lines 7450-7949 of pqc-developers-handbook.md
- **Description**: Module-LWE Public Key Encryption (K-PKE)
- **Features**:
  - K-PKE key generation using Module-LWE
  - IND-CPA secure encryption/decryption
  - Message encoding/decoding for 256-bit messages
  - Malleability attack demonstration (why CPA-only is insufficient)
  - Key and ciphertext size analysis
- **Compilation**: `gcc -Wall -o unit_3_4_kpke unit_3_4_kpke.c`
- **Note**: Educational implementation - NOT for production use. For CCA security, the FO transform must be applied (see Module 4).

## Compilation Instructions

### Compile All Programs

Use the provided script:
```bash
chmod +x compile_all.sh
./compile_all.sh
```

### Compile Individual Programs

```bash
# Unit 3.1
gcc -Wall -o unit_3_1_lattice_basics unit_3_1_lattice_basics.c -lm

# Unit 3.2
gcc -Wall -o unit_3_2_lwe_basics unit_3_2_lwe_basics.c
gcc -Wall -o unit_3_2_brute_force_lwe unit_3_2_brute_force_lwe.c

# Unit 3.3
gcc -Wall -o unit_3_3_module_lwe unit_3_3_module_lwe.c
gcc -Wall -o unit_3_3_anticirculant_demo unit_3_3_anticirculant_demo.c

# Unit 3.4
gcc -Wall -o unit_3_4_kpke unit_3_4_kpke.c
```

## Running the Programs

After compilation, run each program:

```bash
./unit_3_1_lattice_basics
./unit_3_2_lwe_basics
./unit_3_2_brute_force_lwe
./unit_3_3_module_lwe
./unit_3_3_anticirculant_demo
./unit_3_4_kpke
```

## Summary

| File | Lines in Source | Unit | Purpose |
|------|----------------|------|---------|
| unit_3_1_lattice_basics.c | 4860-5036 | 3.1 | Lattice fundamentals and hard problems |
| unit_3_2_lwe_basics.c | 5576-5739 | 3.2 | LWE encryption scheme |
| unit_3_2_brute_force_lwe.c | 5937-6028 | 3.2 | Brute force attack demonstration |
| unit_3_3_module_lwe.c | 6333-6501 | 3.3 | Module-LWE structure |
| unit_3_3_anticirculant_demo.c | 6711-6838 | 3.3 | Anti-circulant matrices |
| unit_3_4_kpke.c | 7450-7949 | 3.4 | K-PKE encryption scheme |
| unit_3_1_is_lattice_point.c | 3.1 | 3.1 | Test whether a vector is a lattice point |
| lattice_basics.c | 3.1 | 3.1 | Standalone lattice-basics demo |

**Total Programs**: 8

All programs have been successfully extracted, documented, and tested for compilation.

## Compilation Status

All programs compile successfully without warnings or errors.

✅ **Status**: All 8 programs compiled successfully
