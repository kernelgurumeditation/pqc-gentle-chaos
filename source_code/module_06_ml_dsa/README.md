# Module 6: ML-DSA Deep Dive - C Programs

This directory contains all complete C programs extracted from Module 6 (ML-DSA Deep Dive) of the PQC Developer's Handbook.

## Overview

**Module 6** spans lines 14153-24420 in `pqc-developers-handbook.md` and provides a comprehensive treatment of ML-DSA (Module-Lattice Digital Signature Algorithm), covering everything from basic structures to complete implementation.

**Total Programs:** 13 complete C programs with `int main()`

## Programs List

### Unit 6.1: ML-DSA Structure and Security Model

1. **unit_6_1_ml_dsa_structure.c** (Line 14724)
   - Demonstrates ML-DSA data structures and parameter sets
   - Shows decomposition, hint mechanism, and rejection bounds
   - **Status:** ✓ Extracted and ready

2. **unit_6_1_decomposition_impl.c** (Line 15060)
   - Implements HighBits and LowBits decomposition
   - Verifies decomposition correctness with 10,000 random tests
   - Exercise 6.1.4 solution
   - **Status:** ✓ Extracted and ready

### Unit 6.2: Rejection Sampling in Detail

3. **unit_6_2_rejection_sampling.c** (Line 15692)
   - Demonstrates rejection sampling algorithm
   - Shows distribution analysis and empirical testing
   - Includes constant-time implementations

4. **unit_6_2_rejection_probability.c** (Line 16033)
   - Analyzes rejection probabilities for different parameters
   - Compares exact vs approximate calculations
   - Exercise 6.2.4 solution

### Unit 6.3: ML-DSA Key Generation

5. **unit_6_3_key_generation.c** (Line 16753)
   - Complete key generation implementation
   - Matrix expansion, secret sampling, Power2Round
   - Verifies key relationship t = A·s1 + s2

6. **unit_6_3_keypair_verification.c** (Line 17272)
   - Verifies key pair consistency
   - Checks all ML-DSA key requirements
   - Exercise 6.3.4 solution

### Unit 6.4: ML-DSA Signing (with Retry Loop)

7. **unit_6_4_signing_experiments.c** (Line 18692)
   - Demonstrates signing with rejection sampling
   - Analyzes iteration counts empirically

8. **unit_6_4_rejection_distribution.c** (Line 19009)
   - Detailed analysis of rejection distribution
   - Histograms of attempt counts

### Unit 6.5: ML-DSA Verification

9. **unit_6_5_verification_demo.c** (Line 20068)
   - Complete verification algorithm
   - UseHint demonstration
   - Signature validation

### Unit 6.6: Encoding and Serialization

10. **unit_6_6_encoding_tests.c** (Line 21334)
    - Tests z-coefficient encoding
    - Tests hint encoding
    - Compares with ECDSA sizes

### Unit 6.7: Complete ML-DSA Implementation

11. **unit_6_7_complete_implementation.c** (Line 22623)
    - Full ML-DSA-65 implementation
    - Complete sign and verify flow
    - Production-like structure

12. **unit_6_7_benchmarking.c** (Line 23076)
    - Performance benchmarks
    - Analyzes signing iteration distribution
    - Timing measurements

13. **unit_6_7_test_suite.c** (Line 24029)
    - Comprehensive test suite
    - Tests all ML-DSA components
    - Known answer tests

## Extraction Tools

### Method 1: Manual Extraction (Completed for programs 1-2)

Programs 1 and 2 have been manually extracted and verified.

### Method 2: Automated Extraction (Recommended)

Use the provided Python script:

```bash
python3 extract_programs.py
```

This will extract all remaining programs (3-13) automatically.

### Method 3: Semi-Automated

Use the extraction report to manually locate and extract specific programs:

```bash
# View the extraction report
cat EXTRACTION_REPORT.md

# Extract programs at specific line numbers
# Example for program 3 (line 15692):
sed -n '15443,15819p' ../../pqc-developers-handbook.md | grep -A 300 "```c" | head -n 280 > unit_6_2_rejection_sampling.c
```

## Compilation

### Compile All Programs

```bash
chmod +x compile_all.sh
./compile_all.sh
```

### Compile Individual Programs

```bash
gcc -Wall -Wextra -std=c99 -o output unit_6_1_ml_dsa_structure.c
./output
```

### Quick Test (Currently Extracted)

```bash
chmod +x test_extracted.sh
./test_extracted.sh
```

## Program Characteristics

All programs in this module:

- **Language:** C99
- **Target:** ML-DSA-65 (NIST Security Level 3)
- **Purpose:** Educational demonstrations
- **Security:** NOT production-ready (simplified implementations)
- **Dependencies:** Standard C library, some use simplified PRNG instead of SHAKE256

## Common Parameters (ML-DSA-65)

```c
#define N 256              // Polynomial degree
#define Q 8380417          // Prime modulus (2^23 - 2^13 + 1)
#define K 6                // Matrix rows
#define L 5                // Matrix columns
#define ETA 4              // Secret coefficient bound
#define GAMMA1 524288      // Masking bound (2^19)
#define GAMMA2 261888      // Decomposition parameter ((Q-1)/32)
#define TAU 49             // Challenge weight
#define BETA 196           // Rejection bound (TAU * ETA)
#define OMEGA 55           // Max hint weight
#define D 13               // Dropped bits in t1
```

## Expected Sizes

| Component | Size (bytes) |
|-----------|--------------|
| Public Key | 1,952 |
| Secret Key | 4,032 |
| Signature | ~3,293 |

## Testing Notes

### Compilation Requirements

- **Compiler:** GCC 7.0+ or Clang 6.0+
- **Standard:** C99 or later
- **Math Library:** `-lm` (for some programs)
- **Warnings:** `-Wall -Wextra` recommended

### Known Limitations

1. **SHAKE256/SHAKE128:** Some programs use simplified PRNGs instead of proper SHAKE functions
2. **NTT:** Some programs use schoolbook polynomial multiplication instead of optimized NTT
3. **Constant-time:** Educational implementations may not be fully constant-time
4. **Randomness:** Uses `rand()` for demonstration (not cryptographically secure)

### Expected Behavior

- Programs should compile without warnings
- Most programs print educational output showing parameter values and test results
- Larger programs (complete implementation, benchmarking) may take several seconds to run
- Rejection sampling programs show probabilistic behavior

## Further Reading

Each program corresponds to a specific section in the PQC Developer's Handbook:

- **Module 6 location:** Lines 14153-24420 in `/home/nuno/next-gig/pqc-developers-handbook.md`
- **Related modules:** Module 2 (Math Foundations), Module 3 (Lattice Crypto), Module 5 (Signatures)

## Directory Structure

```
module_06_ml_dsa/
├── README.md (this file)
├── EXTRACTION_REPORT.md
├── extract_programs.py
├── compile_all.sh
├── test_extracted.sh
├── unit_6_1_ml_dsa_structure.c         ✓ Extracted
├── unit_6_1_decomposition_impl.c       ✓ Extracted
├── unit_6_2_rejection_sampling.c       (Run extract_programs.py)
├── unit_6_2_rejection_probability.c    (Run extract_programs.py)
├── unit_6_3_key_generation.c           (Run extract_programs.py)
├── unit_6_3_keypair_verification.c     (Run extract_programs.py)
├── unit_6_4_signing_experiments.c      (Run extract_programs.py)
├── unit_6_4_rejection_distribution.c   (Run extract_programs.py)
├── unit_6_5_verification_demo.c        (Run extract_programs.py)
├── unit_6_6_encoding_tests.c           (Run extract_programs.py)
├── unit_6_7_complete_implementation.c  (Run extract_programs.py)
├── unit_6_7_benchmarking.c             (Run extract_programs.py)
└── unit_6_7_test_suite.c               (Run extract_programs.py)
```

## Quick Start

```bash
# 1. Extract all programs
python3 extract_programs.py

# 2. Compile all programs
chmod +x compile_all.sh
./compile_all.sh

# 3. Run a specific program
gcc -Wall -o demo unit_6_1_ml_dsa_structure.c
./demo

# 4. Clean up binaries
rm -f unit_6_*_*.o demo test1 test2
```

## License

These programs are educational implementations extracted from the PQC Developer's Handbook. They are for learning purposes only and should not be used in production systems.
