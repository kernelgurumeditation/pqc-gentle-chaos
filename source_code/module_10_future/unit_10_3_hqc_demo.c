/*
 * unit_10_3_hqc_demo.c
 *
 * HQC (Hamming Quasi-Cyclic) KEM demo via liboqs.
 *
 * *** SECURITY WARNING ***
 * HQC has three documented CVEs as of April 2026:
 *   CVE-2024-54137 — implicit-rejection sigma field mishandled (Dec 2024)
 *   CVE-2025-48946 — design flaw (May 2025): HQC disabled by default in liboqs 0.13+
 *   CVE-2025-52473 — Clang 17–20 optimizer breaks constant-time (July 2025)
 *
 * FIPS 207 (HQC KEM) IPD is targeted for 2026, final 2027.
 *
 * DO NOT use HQC in production as of April 2026. This demo exists to
 * illustrate the API for when the standard finalizes and implementations
 * mature.
 *
 * Maps to: Handbook Unit 10.1 (NIST backup KEM) and Unit 11.10 (CVE registry).
 *
 * Build:
 *   gcc -Wall -Wextra -Wshadow -O2 -std=c11 -DHAVE_LIBOQS -o hqc_demo unit_10_3_hqc_demo.c -loqs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>

int main(void) {
    printf("HQC KEM demo via liboqs\n");
    printf("=======================\n");
    printf("\n");
    printf("*** SECURITY WARNING ***\n");
    printf("HQC is disabled by default in liboqs 0.13+ pending spec revision.\n");
    printf("Do NOT use in production. Three CVEs in 18 months (see Unit 11.10).\n");
    printf("This demo runs only if you have explicitly re-enabled HQC in your\n");
    printf("liboqs build (not recommended).\n\n");

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    if (!kem) {
        fprintf(stderr, "HQC-128 not available in this liboqs build.\n");
        fprintf(stderr, "(This is the expected state; HQC is disabled for safety.)\n");
        return 1;
    }

    printf("Algorithm:      %s\n", kem->method_name);
    printf("Public key:     %zu bytes\n", kem->length_public_key);
    printf("Secret key:     %zu bytes\n", kem->length_secret_key);
    printf("Ciphertext:     %zu bytes\n", kem->length_ciphertext);
    printf("Shared secret:  %zu bytes\n", kem->length_shared_secret);

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss_enc || !ss_dec) goto cleanup;
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) goto cleanup;
    if (OQS_KEM_encaps(kem, ct, ss_enc, pk) != OQS_SUCCESS) goto cleanup;
    if (OQS_KEM_decaps(kem, ss_dec, ct, sk) != OQS_SUCCESS) goto cleanup;

    int ok = (memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0);
    printf("Encaps/Decaps match: %s\n", ok ? "YES" : "NO");

cleanup:
    if (sk) OQS_MEM_cleanse(sk, kem->length_secret_key);
    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    OQS_KEM_free(kem);
    return 0;
}

#else

int main(void) {
    printf("HQC KEM demo — requires liboqs.\n");
    printf("\n");
    printf("HQC status (April 2026): disabled by default in liboqs 0.13+ due to\n");
    printf("implementation CVEs. See Handbook Unit 11.10 for the CVE registry.\n");
    printf("\n");
    printf("Expected parameter sets (NIST Round 4 / FIPS 207 IPD forthcoming):\n");
    printf("  HQC-128:  pk=2249, sk=2289, ct=4481, ss=32\n");
    printf("  HQC-192:  pk=4522, sk=4562, ct=9026, ss=64\n");
    printf("  HQC-256:  pk=7245, sk=7285, ct=14469, ss=64\n");
    return 0;
}

#endif
