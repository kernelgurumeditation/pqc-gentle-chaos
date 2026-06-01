#!/usr/bin/env bash
# golden.sh — record / check golden output fixtures for the deterministic
# reference programs.
#
#   ./golden.sh record   # (re)generate expected/<module>/<prog>.out for all
#                         #  deterministic programs
#   ./golden.sh check     # run each program and diff against its fixture;
#                         #  exit non-zero on any mismatch or missing fixture
#
# Only programs whose output is DETERMINISTIC are covered. Excluded by design:
#   - timing / benchmark programs (wall-clock numbers vary): *benchmark*,
#     unit_2_1_fermat_inverse (prints elapsed seconds), unit_11_8_timing_test
#   - programs that intentionally use fresh randomness each run:
#     unit_11_2_x25519_key_exchange, the unit_8_5 suites
#   - programs needing liboqs/OpenSSL that may not build here (handled per-module)
#
# All covered programs honor the PQC_DEMO_SEED seam; we run with a fixed seed
# so output is reproducible.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
MODE="${1:-check}"
SEED="${PQC_DEMO_SEED:-1234567}"
export PQC_DEMO_SEED="$SEED"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Deterministic, standalone programs (relative paths). Kept explicit so a new
# non-deterministic program can't silently join the golden set.
PROGRAMS="
module_02_math_foundations/unit_2_1_barrett
module_02_math_foundations/unit_2_1_gcd_extended
module_02_math_foundations/unit_2_1_mod_basic
module_02_math_foundations/unit_2_1_mod_exp
module_02_math_foundations/unit_2_1_test_barrett
module_02_math_foundations/unit_2_2_check_inverse
module_02_math_foundations/unit_2_2_rq_basic
module_02_math_foundations/unit_2_2_verify_x256
module_02_math_foundations/unit_2_3_bitpack
module_02_math_foundations/unit_2_3_compress
module_02_math_foundations/unit_2_3_negacyclic_test
module_02_math_foundations/unit_2_3_poly_add_sub
module_02_math_foundations/unit_2_3_poly_infnorm
module_02_math_foundations/unit_2_3_poly_mul_naive
module_02_math_foundations/unit_2_4_matvec
module_02_math_foundations/unit_2_4_polyvec_infnorm
module_02_math_foundations/unit_2_5_ntt
module_02_math_foundations/unit_2_5_verify_twiddle
module_02_math_foundations/unit_2_6_cbd
module_03_lattice_theory/unit_3_1_is_lattice_point
module_03_lattice_theory/unit_3_1_lattice_basics
module_03_lattice_theory/unit_3_2_brute_force_lwe
module_03_lattice_theory/unit_3_2_lwe_basics
module_03_lattice_theory/unit_3_3_anticirculant_demo
module_03_lattice_theory/unit_3_3_module_lwe
module_03_lattice_theory/unit_3_4_kpke
module_04_ml_kem/unit_4_1_kem_concepts
module_04_ml_kem/unit_4_2_kpke
module_04_ml_kem/unit_4_2_kpke_full
module_04_ml_kem/unit_4_3_fo_transform
module_04_ml_kem/unit_4_4_mlkem768_e2e
module_05_signatures_theory/unit_5_1_signature_security
module_05_signatures_theory/unit_5_2_fiat_shamir
module_05_signatures_theory/unit_5_3_lattice_signatures
module_06_ml_dsa/unit_6_1_ml_dsa_structure
module_06_ml_dsa/unit_6_2_rejection_probability
module_06_ml_dsa/unit_6_3_keypair_verification
module_06_ml_dsa/unit_6_6_encoding
module_06_ml_dsa/unit_6_7_complete_impl_full
module_06_ml_dsa/unit_6_9_test_suite
module_06_ml_dsa/unit_6_10_self_test
module_07_slh_dsa/unit_7_1_lamport_signatures
module_07_slh_dsa/unit_7_2_merkle_tree_tests
module_07_slh_dsa/unit_7_3_wots_key_reuse_attack
module_07_slh_dsa/unit_7_3_wots_tests
module_07_slh_dsa/unit_7_5_fors_tests
module_07_slh_dsa/unit_7_7_integration_tests
module_08_hybrid/unit_8_2_xwing_test_suite
module_08_hybrid/unit_8_3_hybrid_signature_test
module_09_protocols/unit_9_2_ssh_kex_demo
module_09_protocols/unit_9_4_ipsec_ike_mlkem
module_09_protocols/unit_9_5_hybrid_code_signing
module_10_future/unit_10_1_crypto_agility
module_11_migration/unit_11_1_rsa_toy_example
module_11_migration/unit_11_5_toy_lwe_encryption
"

pass=0; fail=0; missing=0; skip=0
for prog in $PROGRAMS; do
  [ -z "$prog" ] && continue
  exp="expected/$prog.out"
  if [ ! -x "$prog" ]; then
    echo -e "${YELLOW}[SKIP]${NC} $prog (not built — run 'make all' first)"
    skip=$((skip + 1)); continue
  fi
  out="$(./"$prog" 2>&1)"
  if [ "$MODE" = "record" ]; then
    mkdir -p "$(dirname "$exp")"
    printf '%s\n' "$out" > "$exp"
    echo -e "${GREEN}[REC ]${NC} $exp"
    pass=$((pass + 1))
  else
    if [ ! -f "$exp" ]; then
      echo -e "${RED}[MISS]${NC} $prog (no fixture — run 'make golden' to record)"
      missing=$((missing + 1)); continue
    fi
    if diff -q <(printf '%s\n' "$out") "$exp" >/dev/null 2>&1; then
      echo -e "${GREEN}[ OK ]${NC} $prog"
      pass=$((pass + 1))
    else
      echo -e "${RED}[FAIL]${NC} $prog (output differs from $exp)"
      diff <(printf '%s\n' "$out") "$exp" | head -8 | sed 's/^/        /'
      fail=$((fail + 1))
    fi
  fi
done

echo ""
if [ "$MODE" = "record" ]; then
  echo -e "Recorded ${GREEN}$pass${NC} fixtures, skipped ${YELLOW}$skip${NC}."
  exit 0
fi
echo -e "golden-check: ${GREEN}$pass passed${NC}, ${RED}$fail failed${NC}, ${RED}$missing missing${NC}, ${YELLOW}$skip skipped${NC}."
{ [ "$fail" -gt 0 ] || [ "$missing" -gt 0 ]; } && exit 1
exit 0
