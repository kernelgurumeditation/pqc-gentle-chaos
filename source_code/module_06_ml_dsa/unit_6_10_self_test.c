/*
 * Module 6: ML-DSA (Dilithium) - Parameter Self-Consistency Checker
 * Unit 6.10: Runtime verification of ML-DSA-65 parameter consistency
 *
 * This program recomputes the DERIVED ML-DSA-65 parameters and sizes from the
 * base parameters (n, q, k, l, eta, tau, d, gamma1, omega, ...) and asserts
 * that they equal the published FIPS 204 constants. For each check it prints
 * PASS or FAIL, and the program exits with a NONZERO status on any mismatch.
 *
 * Purpose: catch transcription / refactoring errors in the educational sources
 * of this module (e.g. a wrong beta, c_tilde, gamma2, t1_bits, pk or sig size).
 *
 * IMPORTANT: This is a PARAMETER / self-CONSISTENCY checker. It verifies that
 * the derived sizes are internally consistent with the base parameters and the
 * published table values. It is NOT a NIST Known-Answer-Test (KAT) and does
 * NOT validate any implementation against official NIST test vectors.
 *
 * Compile: gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o unit_6_10_self_test \
 *              unit_6_10_self_test.c
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ *
 * Base ML-DSA-65 parameters (FIPS 204, Table 1).                     *
 * Everything else in this file is DERIVED from these.                *
 * ------------------------------------------------------------------ */
#define BASE_N        256
#define BASE_Q        8380417       /* = 2^23 - 2^13 + 1 */
#define BASE_K        6
#define BASE_L        5
#define BASE_ETA      4
#define BASE_TAU      49
#define BASE_D        13
#define BASE_GAMMA1   (1 << 19)     /* ML-DSA-65: gamma1 = 2^19 */
#define BASE_OMEGA    55
#define BASE_SEED_BYTES 32          /* rho / seed length */

/* ------------------------------------------------------------------ *
 * Published (expected) values we will check the derivations against. *
 * ------------------------------------------------------------------ */
#define PUB_Q         8380417
#define PUB_CTILDE    48
#define PUB_BETA      196
#define PUB_GAMMA2    261888
#define PUB_T1_BITS   10
#define PUB_PK_BYTES  1952
#define PUB_SIG_BYTES 3309

/* Number of bits needed to represent x (0 -> 0). */
static int bitlen(uint32_t x) {
    int b = 0;
    while (x) { b++; x >>= 1; }
    return b;
}

/* Single check helper: prints PASS/FAIL and returns 1 on pass, 0 on fail. */
static int check(const char *label, long derived, long expected) {
    int ok = (derived == expected);
    printf("  [%s] %-46s derived=%ld expected=%ld\n",
           ok ? "PASS" : "FAIL", label, derived, expected);
    return ok;
}

int main(void) {
    printf("=== ML-DSA-65 Parameter Self-Consistency Checker ===\n");
    printf("(Self-consistency only - NOT a NIST KAT / not vector-validated)\n\n");

    int all_ok = 1;

    /* ---- q --------------------------------------------------------- *
     * q = 2^23 - 2^13 + 1.                                             */
    long q_derived = (1L << 23) - (1L << 13) + 1L;
    all_ok &= check("q = 2^23 - 2^13 + 1", q_derived, PUB_Q);
    all_ok &= check("q (base macro)", BASE_Q, PUB_Q);

    /* ---- beta = tau * eta ----------------------------------------- */
    long beta_derived = (long)BASE_TAU * BASE_ETA;
    all_ok &= check("beta = tau * eta = 49 * 4", beta_derived, PUB_BETA);

    /* ---- gamma2 = (q - 1) / 32 ------------------------------------ *
     * ML-DSA-65 / ML-DSA-87 use (q-1)/32.                             */
    long gamma2_derived = (BASE_Q - 1) / 32;
    all_ok &= check("gamma2 = (q - 1) / 32", gamma2_derived, PUB_GAMMA2);

    /* ---- t1 bit width = bitlen(q-1) - d --------------------------- *
     * Top bits of t after dropping the low d bits.                    */
    long t1_bits_derived = bitlen((uint32_t)(BASE_Q - 1)) - BASE_D;
    all_ok &= check("t1_bits = bitlen(q-1) - d", t1_bits_derived, PUB_T1_BITS);

    /* ---- c_tilde (challenge hash) length -------------------------- *
     * ML-DSA-65 uses lambda/4 = 192/4 = 48 bytes (lambda = 2*192).    *
     * Equivalently 2 * (collision security in bytes). We derive from  *
     * the NIST Level-3 collision strength of 192 bits.                */
    long lambda_bits = 192;                 /* NIST Level 3 target */
    long ctilde_derived = (2 * lambda_bits) / 8;  /* 2*lambda bits -> bytes */
    all_ok &= check("c_tilde = (2*192)/8 bytes", ctilde_derived, PUB_CTILDE);

    /* ---- public key size ------------------------------------------ *
     * pk = seed(rho) + k * (n * t1_bits / 8).                         */
    long polyt1_bytes = (long)BASE_N * PUB_T1_BITS / 8;     /* per poly */
    long pk_derived = BASE_SEED_BYTES + (long)BASE_K * polyt1_bytes;
    all_ok &= check("polyt1 = n*t1_bits/8 (per poly)", polyt1_bytes, 320);
    all_ok &= check("pk = 32 + k*polyt1", pk_derived, PUB_PK_BYTES);

    /* ---- signature size ------------------------------------------- *
     * sig = c_tilde + l*polyz + (omega + k).                          *
     * polyz packs each z coeff in bitlen(2*gamma1 - 1) bits.          */
    int z_bits = bitlen((uint32_t)(2 * BASE_GAMMA1 - 1));   /* = 20 */
    long polyz_bytes = (long)BASE_N * z_bits / 8;           /* per poly */
    long hint_bytes = BASE_OMEGA + BASE_K;
    long sig_derived = PUB_CTILDE + (long)BASE_L * polyz_bytes + hint_bytes;
    all_ok &= check("z_bits = bitlen(2*gamma1-1)", z_bits, 20);
    all_ok &= check("polyz = n*z_bits/8 (per poly)", polyz_bytes, 640);
    all_ok &= check("sig = c_tilde + l*polyz + (omega+k)",
                    sig_derived, PUB_SIG_BYTES);

    printf("\n");
    if (all_ok) {
        printf("=== ALL CHECKS PASSED: parameters are self-consistent ===\n");
        return EXIT_SUCCESS;
    }
    printf("=== ONE OR MORE CHECKS FAILED: parameter mismatch ===\n");
    return EXIT_FAILURE;
}
