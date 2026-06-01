/*
 * verify_params.c — self-consistency checker for the shared FIPS parameter set.
 *
 * Recomputes the derived key/signature SIZES from base parameters and asserts
 * they equal the published totals in fips_params.h. This is a PARAMETER
 * self-consistency check (NOT a NIST Known-Answer-Test against test vectors).
 *
 * Build:  cc -Wall -Wextra -Wshadow -O2 -std=c11 -I. -o verify_params common/verify_params.c
 * Run:    ./verify_params      (exit 0 = all consistent, 1 = mismatch)
 */
#include <stdio.h>
#include "fips_params.h"

static int g_fail = 0;

static void check(const char *name, long got, long want)
{
    if (got == want) {
        printf("[PASS] %-34s = %ld\n", name, got);
    } else {
        printf("[FAIL] %-34s = %ld (expected %ld)\n", name, got, want);
        g_fail = 1;
    }
}

int main(void)
{
    printf("FIPS parameter self-consistency check\n");
    printf("=====================================\n");

    /* ML-DSA-65 derived sizes (FIPS 204). */
    check("ML-DSA-65 beta = tau*eta",
          (long)MLDSA65_TAU * MLDSA65_ETA, MLDSA65_BETA);
    check("ML-DSA-65 gamma2 = (q-1)/32",
          (MLDSA_Q - 1) / 32, MLDSA65_GAMMA2);
    check("ML-DSA-65 pk = 32 + k*n*t1bits/8",
          32L + (long)MLDSA65_K * MLDSA_N * MLDSA65_T1_BITS / 8, MLDSA65_PK_BYTES);
    /* sig = c_tilde + l*n*(1+log2 gamma1 .. )/8 + (omega + k).
       z is packed at 20 bits/coeff for gamma1 = 2^19. */
    check("ML-DSA-65 sig = ctilde + l*n*20/8 + (omega+k)",
          (long)MLDSA65_CTILDE + (long)MLDSA65_L * MLDSA_N * 20 / 8
              + (MLDSA65_OMEGA + MLDSA65_K),
          MLDSA65_SIG_BYTES);

    /* ML-KEM-768 derived sizes (FIPS 203). */
    check("ML-KEM-768 ek = 384*k + 32",
          384L * MLKEM768_K + 32, MLKEM768_EK_BYTES);
    check("ML-KEM-768 ct = 32*(du*k + dv)",
          32L * (MLKEM768_DU * MLKEM768_K + MLKEM768_DV), MLKEM768_CT_BYTES);
    check("ML-KEM Montgomery R = 2^16 mod q",
          65536L % MLKEM_Q, MLKEM_MONT_R);

    /* WOTS+ (n=32, w=16). */
    check("WOTS+ len = len1 + len2",
          (long)WOTS_N32_W16_LEN1 + WOTS_N32_W16_LEN2, WOTS_N32_W16_LEN);

    /* X-Wing composition. */
    check("X-Wing sk = 32 + ML-KEM-768 dk",
          32L + MLKEM768_DK_BYTES, XWING_SK_BYTES);
    check("X-Wing pk = 32 + ML-KEM-768 ek",
          32L + MLKEM768_EK_BYTES, XWING_PK_BYTES);
    check("X-Wing ct = 32 + ML-KEM-768 ct",
          32L + MLKEM768_CT_BYTES, XWING_CT_BYTES);

    printf("\n");
    if (g_fail) {
        printf("RESULT: FAIL — parameter set is inconsistent.\n");
        return 1;
    }
    printf("RESULT: PASS — all derived sizes match published constants.\n");
    return 0;
}
