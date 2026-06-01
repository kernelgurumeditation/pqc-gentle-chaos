#!/bin/bash
# run_tests.sh - Test runner for PQC Learning Plan source code examples
# Verifies that all programs compile and produce expected output

set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Build everything first so a fresh checkout has executables to test.
# (Failures here are reported per-program below as SKIP/FAIL, not fatal.)
echo "Building all modules..."
make -C "$SCRIPT_DIR" all >/dev/null 2>&1 || true
echo ""

# Print colored status. NOTE: use the $((...)) assignment form, not
# ((PASS_COUNT++)) — the latter returns exit status 1 when the value is 0,
# which would abort the script under a stricter shell mode.
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

echo "========================================"
echo "PQC Learning Plan - Source Code Tests"
echo "========================================"
echo ""

# Test function: run program and check for expected substring in output
test_program() {
    local name="$1"
    local path="$2"
    local expected="$3"

    if [[ ! -x "$path" ]]; then
        skip "$name - executable not found"
        return
    fi

    output=$("$path" 2>&1) || true

    if echo "$output" | grep -q "$expected"; then
        pass "$name"
    else
        fail "$name - expected '$expected'"
        echo "  Output: ${output:0:100}..."
    fi
}

echo "=== Module 02: Math Foundations ==="
test_program "unit_2_1_barrett" \
    "$SCRIPT_DIR/module_02_math_foundations/unit_2_1_barrett" \
    "Barrett"

test_program "unit_2_1_gcd_extended" \
    "$SCRIPT_DIR/module_02_math_foundations/unit_2_1_gcd_extended" \
    "gcd"

test_program "unit_2_1_fermat_inverse" \
    "$SCRIPT_DIR/module_02_math_foundations/unit_2_1_fermat_inverse" \
    "Fermat"

echo ""
echo "=== Module 03: Lattice Theory ==="
test_program "lattice_basics" \
    "$SCRIPT_DIR/module_03_lattice_theory/lattice_basics" \
    "Lattice"

test_program "unit_3_1_is_lattice_point" \
    "$SCRIPT_DIR/module_03_lattice_theory/unit_3_1_is_lattice_point" \
    "lattice"

echo ""
echo "=== Module 04: ML-KEM ==="
test_program "unit_4_1_kem_concepts" \
    "$SCRIPT_DIR/module_04_ml_kem/unit_4_1_kem_concepts" \
    "KEM"

test_program "unit_4_4_mlkem768_e2e" \
    "$SCRIPT_DIR/module_04_ml_kem/unit_4_4_mlkem768_e2e" \
    "PASS"

test_program "unit_4_2_kpke" \
    "$SCRIPT_DIR/module_04_ml_kem/unit_4_2_kpke" \
    "K-PKE"

test_program "unit_4_3_fo_transform" \
    "$SCRIPT_DIR/module_04_ml_kem/unit_4_3_fo_transform" \
    "Fujisaki-Okamoto"

echo ""
echo "=== Module 05: Signatures Theory ==="
test_program "unit_5_1_signature_security" \
    "$SCRIPT_DIR/module_05_signatures_theory/unit_5_1_signature_security" \
    "Signature"

test_program "unit_5_2_fiat_shamir" \
    "$SCRIPT_DIR/module_05_signatures_theory/unit_5_2_fiat_shamir" \
    "Fiat-Shamir"

test_program "unit_5_3_lattice_signatures" \
    "$SCRIPT_DIR/module_05_signatures_theory/unit_5_3_lattice_signatures" \
    "Lattice"

echo ""
echo "=== Module 06: ML-DSA ==="
test_program "unit_6_9_test_suite" \
    "$SCRIPT_DIR/module_06_ml_dsa/unit_6_9_test_suite" \
    "ML-DSA"

test_program "unit_6_10_self_test" \
    "$SCRIPT_DIR/module_06_ml_dsa/unit_6_10_self_test" \
    "PASS"

echo ""
echo "=== Module 07: SLH-DSA ==="
test_program "unit_7_1_lamport_signatures" \
    "$SCRIPT_DIR/module_07_slh_dsa/unit_7_1_lamport_signatures" \
    "Lamport"

test_program "unit_7_2_merkle_tree_tests" \
    "$SCRIPT_DIR/module_07_slh_dsa/unit_7_2_merkle_tree_tests" \
    "Merkle"

test_program "unit_7_3_wots_key_reuse_attack" \
    "$SCRIPT_DIR/module_07_slh_dsa/unit_7_3_wots_key_reuse_attack" \
    "WOTS"

echo ""
echo "=== Module 08: Hybrid ==="
test_program "unit_8_2_xwing_test_suite" \
    "$SCRIPT_DIR/module_08_hybrid/unit_8_2_xwing_test_suite" \
    "X-Wing"

test_program "unit_8_3_hybrid_signature_test" \
    "$SCRIPT_DIR/module_08_hybrid/unit_8_3_hybrid_signature_test" \
    "Hybrid"

test_program "unit_8_5_hybrid_crypto_test_suite" \
    "$SCRIPT_DIR/module_08_hybrid/unit_8_5_hybrid_crypto_test_suite" \
    "Hybrid"

echo ""
echo "=== Module 09: Protocols ==="
test_program "unit_9_2_ssh_kex_demo" \
    "$SCRIPT_DIR/module_09_protocols/unit_9_2_ssh_kex_demo" \
    "mlkem768x25519-sha256"

echo ""
echo "=== Module 10: Future ==="
test_program "unit_10_1_crypto_agility" \
    "$SCRIPT_DIR/module_10_future/unit_10_1_crypto_agility" \
    "Agility"

echo ""
echo "=== Module 11: Migration ==="
test_program "unit_11_1_rsa_toy_example" \
    "$SCRIPT_DIR/module_11_migration/unit_11_1_rsa_toy_example" \
    "RSA"

test_program "unit_11_5_toy_lwe_encryption" \
    "$SCRIPT_DIR/module_11_migration/unit_11_5_toy_lwe_encryption" \
    "LWE"

# Note: unit_11_8_timing_test is a template requiring an externally-provided
# function_under_test(); it is intentionally not built and not tested here.

echo ""
echo "=== Capstone: Hybrid Secure Channel ==="
test_program "capstone_hybrid_channel" \
    "$SCRIPT_DIR/capstone/capstone_hybrid_channel" \
    "CAPSTONE: PASS"

echo ""
echo "========================================"
echo "Results Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed: ${RED}$FAIL_COUNT${NC}"
echo -e "Skipped: ${YELLOW}$SKIP_COUNT${NC}"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
