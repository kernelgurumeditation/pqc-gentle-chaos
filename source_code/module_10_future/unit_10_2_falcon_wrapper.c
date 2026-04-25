/*
 * unit_10_2_falcon_wrapper.c
 *
 * FALCON / FN-DSA signing wrapper via liboqs. FIPS 206 is an Initial
 * Public Draft (August 2025); use only for experimentation until the
 * standard finalizes (expected late 2026 or 2027).
 *
 * Maps to: Handbook Unit 10.1 (NIST additional algorithms) and
 *          Appendix Quick Reference (FALCON parameter table).
 *
 * Build with liboqs:
 *   gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o falcon unit_10_2_falcon_wrapper.c -loqs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>

static int demo_falcon(const char *variant) {
    OQS_SIG *sig = OQS_SIG_new(variant);
    if (!sig) {
        fprintf(stderr, "OQS_SIG_new(%s) failed — algorithm not enabled in this liboqs build.\n",
                variant);
        return 1;
    }

    printf("Algorithm:      %s\n", sig->method_name);
    printf("Claimed level:  %u\n", (unsigned)sig->claimed_nist_level);
    printf("Public key:     %zu bytes\n", sig->length_public_key);
    printf("Secret key:     %zu bytes\n", sig->length_secret_key);
    printf("Signature:      up to %zu bytes (variable)\n", sig->length_signature);
    printf("EUF-CMA?:       %s\n", sig->euf_cma ? "yes" : "no");

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *sig_buf = malloc(sig->length_signature);
    size_t sig_len = 0;
    const char *msg = "Post-quantum FALCON test message";

    if (!pk || !sk || !sig_buf) goto cleanup;

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "keypair failed\n");
        goto cleanup;
    }

    if (OQS_SIG_sign(sig, sig_buf, &sig_len, (const uint8_t *)msg, strlen(msg), sk) != OQS_SUCCESS) {
        fprintf(stderr, "sign failed\n");
        goto cleanup;
    }
    printf("Actual sig size: %zu bytes (this signature)\n", sig_len);

    OQS_STATUS vs = OQS_SIG_verify(sig, (const uint8_t *)msg, strlen(msg), sig_buf, sig_len, pk);
    printf("Verification:   %s\n", vs == OQS_SUCCESS ? "VALID" : "INVALID");

cleanup:
    if (sk) OQS_MEM_cleanse(sk, sig->length_secret_key);
    free(pk); free(sk); free(sig_buf);
    OQS_SIG_free(sig);
    return 0;
}

int main(void) {
    printf("FALCON / FN-DSA demo via liboqs\n");
    printf("(FIPS 206 IPD — not yet finalized; for experimentation only)\n\n");

    demo_falcon(OQS_SIG_alg_falcon_512);
    printf("\n---\n\n");
    demo_falcon(OQS_SIG_alg_falcon_1024);

    return 0;
}

#else  /* HAVE_LIBOQS not defined */

int main(void) {
    printf("This demo requires liboqs. Build with: -DHAVE_LIBOQS -loqs\n");
    printf("Install liboqs from https://github.com/open-quantum-safe/liboqs\n");
    printf("\n");
    printf("Expected parameter sets (per FIPS 206 IPD, August 2025):\n");
    printf("  FALCON-512:   pk=897, sk=1281, sig~666 (average), NIST Level 1\n");
    printf("  FALCON-1024:  pk=1793, sk=2305, sig~1280 (average), NIST Level 5\n");
    return 0;
}

#endif
