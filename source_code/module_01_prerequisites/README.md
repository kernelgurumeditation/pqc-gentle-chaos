# Module 1: Prerequisites - Extracted Programs

## test_setup.c

**Location**: `source_code/module_01_prerequisites/test_setup.c`

**Description**: Verifies PQC development environment by testing OpenSSL and liboqs functionality.

**Compilation Requirements**:
- OpenSSL 3.x with SHAKE256 support
- liboqs library installed

**Compile Command**:
```bash
gcc -o test_setup test_setup.c -loqs -lssl -lcrypto
```

**Tests Performed**:
1. OpenSSL SHAKE256 XOF function
2. liboqs ML-KEM-768 (Kyber) key encapsulation
3. liboqs ML-DSA-65 (Dilithium) digital signatures

**Note**: This program requires liboqs to be installed. Follow the installation instructions in the main learning plan document (section 1.2.3) to install liboqs before compiling.

**Expected Output**:
```
=== PQC Development Environment Test ===

OpenSSL version: OpenSSL 3.x.x ...
liboqs version: 0.x.x

Testing OpenSSL SHAKE256... OK
Testing liboqs ML-KEM-768... OK
Testing liboqs ML-DSA-65... OK

=== ALL TESTS PASSED ===
```
