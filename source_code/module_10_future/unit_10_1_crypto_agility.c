/*
 * unit_10_1_crypto_agility.c
 *
 * Cryptographic agility framework: algorithm registry + runtime
 * selection pattern. Demonstrates the provider/dispatcher architecture
 * that enables algorithm swap-out without application code changes.
 *
 * Maps to: Handbook Unit 10.3 (Cryptographic Agility).
 *
 * Build:
 *   gcc -Wall -Wextra -Wshadow -O2 -std=c11 -o crypto_agility unit_10_1_crypto_agility.c
 *
 * Self-contained. This is a framework pattern, not real crypto — replace
 * the placeholder key-gen / sign functions with library calls.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Algorithm identifier — uses NIST-style naming. */
typedef enum {
    ALG_NONE       = 0,
    ALG_ML_KEM_768 = 1,
    ALG_ML_DSA_65  = 2,
    ALG_SLH_DSA_128S = 3,
    ALG_X_WING     = 4,
    ALG_FN_DSA_512 = 5,    /* future: FIPS 206 */
    ALG_HQC_128    = 6,    /* future: FIPS 207 */
} alg_id_t;

/* Capabilities flags — what operations the algorithm supports. */
#define CAP_KEM       0x01
#define CAP_SIGN      0x02
#define CAP_FIPS_140_3 0x10
#define CAP_HYBRID    0x20

/* Provider interface — each algorithm registers one of these. */
typedef struct {
    alg_id_t    id;
    const char *name;
    uint32_t    capabilities;
    size_t      pk_bytes;
    size_t      sk_bytes;
    size_t      ct_or_sig_bytes;
    /* Function pointers — stubs here; real providers fill these in. */
    int (*keygen)(uint8_t *pk, uint8_t *sk);
    int (*sign_or_encap)(uint8_t *out, const uint8_t *in, const uint8_t *key);
    int (*verify_or_decap)(uint8_t *out, const uint8_t *in, const uint8_t *key);
} alg_provider_t;

/* Stub implementations — replace with real library calls. */
static int stub_fn(uint8_t *out, const uint8_t *in, const uint8_t *key) {
    (void)out; (void)in; (void)key;
    return 0;  /* success placeholder */
}
static int stub_keygen(uint8_t *pk, uint8_t *sk) {
    (void)pk; (void)sk;
    return 0;
}

/* Registry — the algorithms the application knows how to use. */
static const alg_provider_t providers[] = {
    { ALG_ML_KEM_768,   "ML-KEM-768",   CAP_KEM | CAP_FIPS_140_3,
      1184, 2400, 1088, stub_keygen, stub_fn, stub_fn },
    { ALG_ML_DSA_65,    "ML-DSA-65",    CAP_SIGN | CAP_FIPS_140_3,
      1952, 4032, 3309, stub_keygen, stub_fn, stub_fn },
    { ALG_SLH_DSA_128S, "SLH-DSA-128s", CAP_SIGN | CAP_FIPS_140_3,
      32, 64, 7856, stub_keygen, stub_fn, stub_fn },
    { ALG_X_WING,       "X-Wing",       CAP_KEM | CAP_HYBRID,
      1216, 2432, 1120, stub_keygen, stub_fn, stub_fn },
    { ALG_FN_DSA_512,   "FN-DSA-512",   CAP_SIGN,  /* FIPS 206 draft — not yet FIPS 140-3 */
      897, 1281, 666, stub_keygen, stub_fn, stub_fn },
    { ALG_HQC_128,      "HQC-128",      CAP_KEM,   /* FIPS 207 IPD — use with caution */
      2249, 2289, 4481, stub_keygen, stub_fn, stub_fn },
    { ALG_NONE, NULL, 0, 0, 0, 0, NULL, NULL, NULL }  /* sentinel */
};

/* Policy-driven selection: given required capabilities, return the best match. */
static const alg_provider_t *select_provider(uint32_t required_caps) {
    for (const alg_provider_t *p = providers; p->id != ALG_NONE; p++) {
        if ((p->capabilities & required_caps) == required_caps) {
            return p;  /* first match in registry order = preference order */
        }
    }
    return NULL;
}

static void describe_provider(const alg_provider_t *p) {
    if (!p) { printf("(no provider)\n"); return; }
    printf("  Algorithm:    %s (id=%d)\n", p->name, p->id);
    printf("  Public key:   %zu bytes\n", p->pk_bytes);
    printf("  Secret key:   %zu bytes\n", p->sk_bytes);
    printf("  Sig/ct:       %zu bytes\n", p->ct_or_sig_bytes);
    printf("  Capabilities: %s%s%s%s\n",
           (p->capabilities & CAP_KEM)        ? "KEM " : "",
           (p->capabilities & CAP_SIGN)       ? "SIGN " : "",
           (p->capabilities & CAP_FIPS_140_3) ? "FIPS140-3 " : "",
           (p->capabilities & CAP_HYBRID)     ? "HYBRID " : "");
}

int main(void) {
    printf("Cryptographic Agility Registry Demo\n");
    printf("====================================\n\n");

    printf("Registry contents:\n");
    for (const alg_provider_t *p = providers; p->id != ALG_NONE; p++) {
        printf("  %2d) %s\n", p->id, p->name);
    }

    printf("\n-- Policy: need FIPS 140-3 KEM --\n");
    const alg_provider_t *kem = select_provider(CAP_KEM | CAP_FIPS_140_3);
    describe_provider(kem);

    printf("\n-- Policy: need FIPS 140-3 signature --\n");
    const alg_provider_t *sig = select_provider(CAP_SIGN | CAP_FIPS_140_3);
    describe_provider(sig);

    printf("\n-- Policy: need hybrid KEM --\n");
    const alg_provider_t *hyb = select_provider(CAP_KEM | CAP_HYBRID);
    describe_provider(hyb);

    printf("\nSwap-out scenario: if ML-KEM-768 is broken, reorder the registry\n");
    printf("so X-Wing or HQC-128 is selected first — no application changes needed.\n");
    return 0;
}
