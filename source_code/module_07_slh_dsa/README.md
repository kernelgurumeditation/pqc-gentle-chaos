# Module 7: SLH-DSA (Hash-Based Digital Signatures) - Code Extracts

This directory contains all complete C programs extracted from Module 7 of the PQC Developer's Handbook.

## Files Overview

### Standalone Programs (Compile Successfully)

1. **unit_7_1_lamport_signatures.c**
   - Source: Unit 7.1 - Hash-Based Signature Foundations
   - Description: Complete Lamport One-Time Signature implementation
   - Features:
     - Key generation, signing, and verification
     - One-time vulnerability demonstration
     - Size comparison with other schemes
   - Compilation: `gcc -Wall -o unit_7_1_lamport_signatures unit_7_1_lamport_signatures.c`
   - Status: ✅ Compiles and runs successfully

### Test Programs (Require Full Implementation)

The following test programs require complete implementation libraries and headers to compile. They are included for reference and study purposes.

2. **unit_7_2_merkle_tree_tests.c**
   - Source: Unit 7.2 - Merkle Trees and One-Time Signatures
   - Requires: `mss.h` (Merkle Signature Scheme implementation)
   - Tests: Merkle tree construction, authentication paths, MSS sign/verify

3. **unit_7_3_wots_tests.c**
   - Source: Unit 7.3 - WOTS+ (Winternitz One-Time Signature Plus)
   - Requires: `wots.h` (WOTS+ implementation)
   - Tests: WOTS+ basic operations, checksum security, base-w conversion, chain functions

4. **unit_7_3_wots_key_reuse_attack.c**
   - Source: Unit 7.3 - WOTS+ Security Analysis
   - Requires: `wots.h` (WOTS+ implementation)
   - Demonstrates: Why WOTS+ keys must never be reused (security vulnerability)

5. **unit_7_5_fors_tests.c**
   - Source: Unit 7.5 - FORS (Few-Time Signatures)
   - Requires: FORS implementation with constants and functions
   - Tests: FORS basic operations, index derivation, wrong message detection

6. **unit_7_7_integration_tests.c**
   - Source: Unit 7.7 - SLH-DSA Implementation and Testing
   - Requires: Both reference and custom SLH-DSA implementations
   - Tests: Interoperability between implementations, cross-verification

## Compilation Status

| File | Compiles Standalone | Notes |
|------|---------------------|-------|
| unit_7_1_lamport_signatures.c | ✅ Yes | Complete working implementation |
| unit_7_2_merkle_tree_tests.c | ❌ No | Requires mss.h |
| unit_7_3_wots_tests.c | ❌ No | Requires wots.h |
| unit_7_3_wots_key_reuse_attack.c | ❌ No | Requires wots.h |
| unit_7_5_fors_tests.c | ❌ No | Requires FORS implementation |
| unit_7_7_integration_tests.c | ❌ No | Requires reference and custom implementations |

## Quick Start

### Running the Lamport Signature Demo

```bash
# Compile
gcc -Wall -o lamport_demo unit_7_1_lamport_signatures.c

# Run
./lamport_demo
```

Expected output:
- Key generation demonstration
- Message signing and verification
- One-time vulnerability analysis
- Size comparison with other signature schemes

## Learning Path

1. **Start with**: `unit_7_1_lamport_signatures.c`
   - Understand the basics of hash-based signatures
   - See why one-time signatures need special handling
   - Compare sizes with modern schemes

2. **Study the test files** (even without compiling):
   - Read `unit_7_2_merkle_tree_tests.c` to understand Merkle tree testing
   - Review `unit_7_3_wots_tests.c` for WOTS+ verification patterns
   - Examine `unit_7_3_wots_key_reuse_attack.c` for security considerations
   - Explore `unit_7_5_fors_tests.c` for few-time signature concepts
   - Analyze `unit_7_7_integration_tests.c` for interoperability patterns

## Module 7 Coverage

These programs cover the following units from Module 7:

- ✅ Unit 7.1: Hash-Based Signature Foundations
- ✅ Unit 7.2: Merkle Trees and One-Time Signatures
- ✅ Unit 7.3: WOTS+ (Winternitz One-Time Signature Plus)
- ❌ Unit 7.4: XMSS Trees and Hypertree (no standalone main())
- ✅ Unit 7.5: FORS (Few-Time Signatures)
- ❌ Unit 7.6: SLH-DSA Complete Algorithm (no standalone main())
- ✅ Unit 7.7: SLH-DSA Implementation and Testing

## Educational Notes

### About Lamport Signatures (Unit 7.1)
The Lamport signature implementation demonstrates:
- **Hash-based security**: Only relies on hash function security
- **One-time use limitation**: Why reusing keys is catastrophic
- **Size tradeoffs**: Why more sophisticated schemes (WOTS+, FORS) were developed
- **Post-quantum security**: Resistant to both classical and quantum attacks

### About the Test Programs
The test programs show professional testing practices:
- Unit testing individual components
- Integration testing across implementations
- Security testing (attack demonstrations)
- Interoperability testing with reference implementations

## Implementation Notes

The complete implementations required by the test programs would include:

1. **mss.h**: Merkle Signature Scheme with tree construction and authentication
2. **wots.h**: WOTS+ with hash chains, checksum, and address structures
3. **FORS**: Few-time signature scheme with multiple trees
4. **SLH-DSA**: Complete FIPS 205 implementation combining all components

These are complex implementations requiring thousands of lines of code, which is why they're not included as single-file programs.

## References

- FIPS 205: Stateless Hash-Based Digital Signature Standard
- Original learning material: pqc-developers-handbook.md (lines 24421-33462)
- Lamport signatures: Original 1979 paper by Leslie Lamport
- SPHINCS+: The predecessor to SLH-DSA

## Author Notes

Extracted from the PQC Developer's Handbook Module 7.
All programs maintain their original structure and comments from the learning material.
