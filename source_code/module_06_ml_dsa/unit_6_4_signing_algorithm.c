/*
 * ML-DSA Signing Implementation
 *
 * This implementation demonstrates the complete signing algorithm
 * with all rejection checks. It uses the same infrastructure from
 * previous units.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ML-DSA-65 parameters */
#define MLDSA_N 256
#define MLDSA_Q 8380417
#define MLDSA_K 6
#define MLDSA_L 5
#define MLDSA_D 13
#define MLDSA_ETA 4
#define MLDSA_TAU 49
#define MLDSA_BETA (MLDSA_TAU * MLDSA_ETA)  /* 196 */
#define MLDSA_GAMMA1 (1 << 19)              /* 524288 */
#define MLDSA_GAMMA2 ((MLDSA_Q - 1) / 32)   /* 261888 */
#define MLDSA_OMEGA 55

/* Signature components */
#define CTILDE_BYTES 48
#define Z_BYTES (MLDSA_L * MLDSA_N * 20 / 8)  /* 20 bits per coeff */
#define H_BYTES (MLDSA_OMEGA + MLDSA_K)       /* Encoded hint */

/* Maximum signing attempts before failure */
#define MAX_SIGN_ATTEMPTS 1000

typedef struct {
    int32_t coeffs[MLDSA_N];
} poly;

typedef struct {
    poly vec[MLDSA_K];
} polyveck;

typedef struct {
    poly vec[MLDSA_L];
} polyvecl;

typedef struct {
    uint8_t ctilde[CTILDE_BYTES];
    polyvecl z;
    uint8_t h[H_BYTES];
    int h_count;  /* Number of hints */
} signature;

/* Forward declarations */
void poly_ntt(poly *p);
void poly_invntt(poly *p);
void poly_pointwise_mul(poly *c, const poly *a, const poly *b);
void poly_add(poly *c, const poly *a, const poly *b);
void poly_sub(poly *c, const poly *a, const poly *b);

/* Constant-time comparison: returns 1 if a >= b, 0 otherwise */
static int32_t ct_ge(int32_t a, int32_t b) {
    return (int32_t)(1 - ((uint32_t)(a - b) >> 31));
}

/* Constant-time absolute value */
static int32_t ct_abs(int32_t x) {
    int32_t mask = x >> 31;
    return (x ^ mask) - mask;
}

/* Constant-time select: returns a if select=1, b if select=0 */
static int32_t ct_select(int32_t a, int32_t b, int32_t select) {
    return b ^ (select & (a ^ b));
}

/*
 * Check if polynomial norm is less than bound (constant-time)
 * Returns 1 if ||p||_inf < bound, 0 otherwise
 */
int poly_check_norm(const poly *p, int32_t bound) {
    int32_t reject = 0;

    for (int i = 0; i < MLDSA_N; i++) {
        int32_t coeff = p->coeffs[i];
        /* Reduce to centered representative */
        coeff = coeff - (ct_ge(coeff, (MLDSA_Q + 1) / 2) & MLDSA_Q);
        int32_t abs_coeff = ct_abs(coeff);
        reject |= ct_ge(abs_coeff, bound);
    }

    return reject == 0;
}

/*
 * Check if vector of l polynomials has norm less than bound
 */
int polyvecl_check_norm(const polyvecl *v, int32_t bound) {
    int result = 1;
    for (int i = 0; i < MLDSA_L; i++) {
        result &= poly_check_norm(&v->vec[i], bound);
    }
    return result;
}

/*
 * Check if vector of k polynomials has norm less than bound
 */
int polyveck_check_norm(const polyveck *v, int32_t bound) {
    int result = 1;
    for (int i = 0; i < MLDSA_K; i++) {
        result &= poly_check_norm(&v->vec[i], bound);
    }
    return result;
}

/*
 * Decompose r into (r1, r0) such that r = r1 * 2*GAMMA2 + r0
 * with -GAMMA2 < r0 <= GAMMA2
 */
void decompose(int32_t r, int32_t *r1, int32_t *r0) {
    /* Ensure r is in [0, Q) */
    r = r % MLDSA_Q;
    if (r < 0) r += MLDSA_Q;

    /* r0 = r mod 2*GAMMA2, centered */
    *r0 = r % (2 * MLDSA_GAMMA2);
    if (*r0 > MLDSA_GAMMA2) {
        *r0 -= 2 * MLDSA_GAMMA2;
    }

    /* Handle special case at q-1 */
    if (r - *r0 == MLDSA_Q - 1) {
        *r1 = 0;
        *r0 -= 1;
    } else {
        *r1 = (r - *r0) / (2 * MLDSA_GAMMA2);
    }
}

/*
 * Extract high bits from polynomial
 */
void poly_highbits(poly *r1, const poly *r) {
    for (int i = 0; i < MLDSA_N; i++) {
        int32_t r1_coeff, r0_coeff;
        decompose(r->coeffs[i], &r1_coeff, &r0_coeff);
        r1->coeffs[i] = r1_coeff;
    }
}

/*
 * Extract low bits from polynomial
 */
void poly_lowbits(poly *r0, const poly *r) {
    for (int i = 0; i < MLDSA_N; i++) {
        int32_t r1_coeff, r0_coeff;
        decompose(r->coeffs[i], &r1_coeff, &r0_coeff);
        r0->coeffs[i] = r0_coeff;
    }
}

/*
 * Apply highbits to vector of k polynomials
 */
void polyveck_highbits(polyveck *r1, const polyveck *r) {
    for (int i = 0; i < MLDSA_K; i++) {
        poly_highbits(&r1->vec[i], &r->vec[i]);
    }
}

/*
 * Apply lowbits to vector of k polynomials
 */
void polyveck_lowbits(polyveck *r0, const polyveck *r) {
    for (int i = 0; i < MLDSA_K; i++) {
        poly_lowbits(&r0->vec[i], &r->vec[i]);
    }
}

/*
 * Compute hint polynomial
 * h[i] = 1 if HighBits(r + z0) != HighBits(r), 0 otherwise
 * Returns the number of 1s in h
 */
int make_hint_poly(poly *h, const poly *z0, const poly *r) {
    int count = 0;

    for (int i = 0; i < MLDSA_N; i++) {
        int32_t r1_a, r0_a, r1_b, r0_b;

        /* HighBits of r */
        decompose(r->coeffs[i], &r1_a, &r0_a);

        /* HighBits of r + z0 */
        int32_t sum = (r->coeffs[i] + z0->coeffs[i]) % MLDSA_Q;
        if (sum < 0) sum += MLDSA_Q;
        decompose(sum, &r1_b, &r0_b);

        /* Hint is 1 if high bits differ */
        h->coeffs[i] = (r1_a != r1_b) ? 1 : 0;
        count += h->coeffs[i];
    }

    return count;
}

/*
 * Compute hint for vector of k polynomials
 * Returns total number of 1s
 */
int make_hint_veck(polyveck *h, const polyveck *z0, const polyveck *r) {
    int total = 0;
    for (int i = 0; i < MLDSA_K; i++) {
        total += make_hint_poly(&h->vec[i], &z0->vec[i], &r->vec[i]);
    }
    return total;
}

/*
 * Sample challenge polynomial c with exactly TAU non-zero coefficients
 * Each non-zero is ±1
 */
void sample_in_ball(poly *c, const uint8_t ctilde[CTILDE_BYTES]) {
    uint8_t buf[136];  /* SHAKE256 rate */
    uint64_t signs;
    int pos;

    /* Initialize c to zero */
    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = 0;
    }

    /* Use SHAKE256 to expand ctilde */
    /* In real implementation: SHAKE256_absorb(ctilde), SHAKE256_squeeze(buf) */
    /* Simplified: use ctilde directly for demonstration */
    memcpy(buf, ctilde, CTILDE_BYTES);
    for (int i = CTILDE_BYTES; i < 136; i++) {
        buf[i] = (uint8_t)(i * 0x9e + ctilde[i % CTILDE_BYTES]);
    }

    /* Extract sign bits */
    signs = 0;
    for (int i = 0; i < 8; i++) {
        signs |= ((uint64_t)buf[i]) << (8 * i);
    }

    /* Fisher-Yates shuffle to place TAU non-zeros */
    pos = 8;
    for (int i = MLDSA_N - MLDSA_TAU; i < MLDSA_N; i++) {
        /* Get random index j in [0, i] */
        int j;
        do {
            if (pos >= 136) {
                /* Need more randomness - re-squeeze */
                pos = 0;
            }
            j = buf[pos++];
        } while (j > i);

        /* Swap positions */
        c->coeffs[i] = c->coeffs[j];

        /* Place ±1 at position j */
        c->coeffs[j] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}

/*
 * Simplified SHAKE256 hash for demonstration
 */
void hash_message(uint8_t mu[64], const uint8_t tr[64],
                  const uint8_t *msg, size_t msglen) {
    /* In real implementation: SHAKE256(tr || msg) */
    /* Simplified version for demonstration */
    for (size_t i = 0; i < 64; i++) {
        mu[i] = tr[i];
        if (i < msglen) {
            mu[i] ^= msg[i];
        }
        mu[i] = (mu[i] * 0x9e + (i * 0x37)) & 0xFF;
    }
}

/*
 * Hash mu and w1 to get challenge seed
 */
void hash_commitment(uint8_t ctilde[CTILDE_BYTES], const uint8_t mu[64],
                     const polyveck *w1) {
    /* In real implementation: SHAKE256(mu || encode(w1)) */
    /* Simplified for demonstration */
    uint8_t temp[CTILDE_BYTES];

    for (int i = 0; i < CTILDE_BYTES; i++) {
        temp[i] = mu[i] ^ mu[i + (64 - CTILDE_BYTES)];
    }

    for (int k = 0; k < MLDSA_K; k++) {
        for (int j = 0; j < MLDSA_N; j += 8) {
            temp[j / 8 % CTILDE_BYTES] ^= (uint8_t)(w1->vec[k].coeffs[j] & 0xFF);
        }
    }

    memcpy(ctilde, temp, CTILDE_BYTES);
}

/*
 * Sample masking vector y with coefficients in [-GAMMA1+1, GAMMA1]
 */
void sample_mask_vector(polyvecl *y, const uint8_t K[32],
                        const uint8_t mu[64], uint16_t nonce) {
    /* In real implementation: ExpandMask using SHAKE256 */
    /* Simplified version for demonstration */

    for (int i = 0; i < MLDSA_L; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            /* Generate pseudorandom value */
            uint32_t seed = K[j % 32] ^ mu[j % 64] ^ nonce ^ (i * 256 + j);
            seed = seed * 1103515245 + 12345;  /* LCG */

            /* Map to [-GAMMA1+1, GAMMA1] */
            int32_t val = (int32_t)(seed % (2 * MLDSA_GAMMA1)) - MLDSA_GAMMA1 + 1;
            y->vec[i].coeffs[j] = val;
        }
    }
}

/*
 * Multiply matrix A by vector (simplified NTT-based)
 * w = A * y
 */
void matrix_vector_mul(polyveck *w, const poly A[MLDSA_K][MLDSA_L],
                       const polyvecl *y) {
    poly temp;

    for (int i = 0; i < MLDSA_K; i++) {
        /* Initialize w[i] to zero */
        for (int j = 0; j < MLDSA_N; j++) {
            w->vec[i].coeffs[j] = 0;
        }

        for (int j = 0; j < MLDSA_L; j++) {
            /* temp = A[i][j] * y[j] */
            poly_pointwise_mul(&temp, &A[i][j], &y->vec[j]);
            poly_add(&w->vec[i], &w->vec[i], &temp);
        }
    }
}

/*
 * Multiply challenge c by secret vector s (k polynomials)
 */
void challenge_times_veck(polyveck *cs, const poly *c, const polyveck *s) {
    for (int i = 0; i < MLDSA_K; i++) {
        poly_pointwise_mul(&cs->vec[i], c, &s->vec[i]);
    }
}

/*
 * Multiply challenge c by secret vector s (l polynomials)
 */
void challenge_times_vecl(polyvecl *cs, const poly *c, const polyvecl *s) {
    for (int i = 0; i < MLDSA_L; i++) {
        poly_pointwise_mul(&cs->vec[i], c, &s->vec[i]);
    }
}

/*
 * Vector subtraction for k polynomials
 */
void polyveck_sub(polyveck *c, const polyveck *a, const polyveck *b) {
    for (int i = 0; i < MLDSA_K; i++) {
        poly_sub(&c->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/*
 * Vector addition for l polynomials
 */
void polyvecl_add(polyvecl *c, const polyvecl *a, const polyvecl *b) {
    for (int i = 0; i < MLDSA_L; i++) {
        poly_add(&c->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/*
 * Negate vector of k polynomials
 */
void polyveck_negate(polyveck *v) {
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            v->vec[i].coeffs[j] = MLDSA_Q - v->vec[i].coeffs[j];
            if (v->vec[i].coeffs[j] == MLDSA_Q) {
                v->vec[i].coeffs[j] = 0;
            }
        }
    }
}

/*
 * Add two vectors of k polynomials
 */
void polyveck_add(polyveck *c, const polyveck *a, const polyveck *b) {
    for (int i = 0; i < MLDSA_K; i++) {
        poly_add(&c->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/*
 * Encode hint into byte array
 * Returns number of bytes written
 */
int encode_hint(uint8_t *h_bytes, const polyveck *h, int h_count) {
    (void)h_count;
    int idx = 0;

    /* For each polynomial in h */
    for (int i = 0; i < MLDSA_K; i++) {
        /* Record positions of 1s */
        for (int j = 0; j < MLDSA_N; j++) {
            if (h->vec[i].coeffs[j] == 1) {
                h_bytes[idx++] = (uint8_t)j;
            }
        }
        /* Mark end of this polynomial's hints */
        h_bytes[MLDSA_OMEGA + i] = (uint8_t)idx;
    }

    /* Fill remaining with zeros */
    while (idx < MLDSA_OMEGA) {
        h_bytes[idx++] = 0;
    }

    return MLDSA_OMEGA + MLDSA_K;
}

/*
 * ML-DSA Signing Algorithm
 *
 * This is the main signing function implementing the complete
 * algorithm with all rejection checks.
 *
 * Returns: 1 on success, 0 on failure (exceeded max attempts)
 */
int mldsa_sign(signature *sig,
               const uint8_t *msg, size_t msglen,
               const uint8_t rho[32],      /* Public seed (used in full impl) */
               const uint8_t K[32],        /* Signing key */
               const uint8_t tr[64],       /* Public key hash */
               const polyvecl *s1,         /* Secret vector */
               const polyveck *s2,         /* Secret vector */
               const polyveck *t0,         /* Low bits of t */
               const poly A[MLDSA_K][MLDSA_L]) /* Public matrix */
{
    (void)rho;
    uint8_t mu[64];          /* Message hash */
    polyvecl y;              /* Masking vector */
    polyveck w, w1;          /* Commitment and decomposition */
    poly c;                  /* Challenge polynomial */
    polyvecl cs1;            /* c * s1 */
    polyveck cs2, ct0;       /* c * s2, c * t0 */
    polyveck r, r0;          /* For second check */
    polyveck neg_ct0;        /* -c * t0 */
    polyveck h;              /* Hint vector */
    uint16_t nonce = 0;      /* Counter for mask sampling */
    int attempts;
    int h_count;

    /* Step 1: Compute message hash */
    hash_message(mu, tr, msg, msglen);

    printf("Signing message of length %zu bytes\n", msglen);
    printf("Starting signing loop...\n");

    /* Main signing loop with rejection sampling */
    for (attempts = 0; attempts < MAX_SIGN_ATTEMPTS; attempts++) {

        /* Step 2: Sample masking vector y */
        sample_mask_vector(&y, K, mu, nonce++);

        /* Step 3: Compute commitment w = A * y */
        matrix_vector_mul(&w, A, &y);

        /* Step 4: Decompose w into high and low bits */
        polyveck_highbits(&w1, &w);

        /* Step 5: Compute challenge hash */
        hash_commitment(sig->ctilde, mu, &w1);

        /* Step 6: Sample challenge polynomial */
        sample_in_ball(&c, sig->ctilde);

        /* Step 7: Compute z = y + c*s1 */
        challenge_times_vecl(&cs1, &c, s1);
        polyvecl_add(&sig->z, &y, &cs1);

        /* ========== REJECTION CHECK 1 ========== */
        /* Check ||z||_inf < gamma1 - beta */
        if (!polyvecl_check_norm(&sig->z, MLDSA_GAMMA1 - MLDSA_BETA)) {
            printf("  Attempt %d: Rejected (z norm too large)\n", attempts + 1);
            continue;
        }

        /* ========== REJECTION CHECK 2 ========== */
        /* Compute r = w - c*s2 and check ||LowBits(r)||_inf < gamma2 - beta */
        challenge_times_veck(&cs2, &c, s2);
        polyveck_sub(&r, &w, &cs2);
        polyveck_lowbits(&r0, &r);

        if (!polyveck_check_norm(&r0, MLDSA_GAMMA2 - MLDSA_BETA)) {
            printf("  Attempt %d: Rejected (r0 norm too large)\n", attempts + 1);
            continue;
        }

        /* ========== REJECTION CHECK 3 ========== */
        /* Compute c*t0 and check ||c*t0||_inf < gamma2 */
        challenge_times_veck(&ct0, &c, t0);

        if (!polyveck_check_norm(&ct0, MLDSA_GAMMA2)) {
            printf("  Attempt %d: Rejected (ct0 norm too large)\n", attempts + 1);
            continue;
        }

        /* ========== COMPUTE HINT ========== */
        /* h = MakeHint(-ct0, r + ct0) */
        neg_ct0 = ct0;
        polyveck_negate(&neg_ct0);

        polyveck r_plus_ct0;
        polyveck_add(&r_plus_ct0, &r, &ct0);

        h_count = make_hint_veck(&h, &neg_ct0, &r_plus_ct0);

        /* ========== REJECTION CHECK 4 ========== */
        /* Check number of hints <= omega */
        if (h_count > MLDSA_OMEGA) {
            printf("  Attempt %d: Rejected (too many hints: %d > %d)\n",
                   attempts + 1, h_count, MLDSA_OMEGA);
            continue;
        }

        /* All checks passed! */
        printf("  Attempt %d: SUCCESS (hints used: %d)\n", attempts + 1, h_count);

        /* Encode the hint */
        sig->h_count = encode_hint(sig->h, &h, h_count);

        return 1;  /* Success */
    }

    printf("Signing FAILED after %d attempts\n", MAX_SIGN_ATTEMPTS);
    return 0;  /* Failure */
}

/*
 * Print signature statistics
 */
void print_signature_info(const signature *sig) {
    printf("\nSignature components:\n");
    printf("  c̃: %02x%02x%02x%02x...%02x%02x%02x%02x (%d bytes)\n",
           sig->ctilde[0], sig->ctilde[1], sig->ctilde[2], sig->ctilde[3],
           sig->ctilde[CTILDE_BYTES-4], sig->ctilde[CTILDE_BYTES-3],
           sig->ctilde[CTILDE_BYTES-2], sig->ctilde[CTILDE_BYTES-1],
           CTILDE_BYTES);

    /* Find z coefficient range */
    int32_t z_min = sig->z.vec[0].coeffs[0];
    int32_t z_max = sig->z.vec[0].coeffs[0];
    for (int i = 0; i < MLDSA_L; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            if (sig->z.vec[i].coeffs[j] < z_min) z_min = sig->z.vec[i].coeffs[j];
            if (sig->z.vec[i].coeffs[j] > z_max) z_max = sig->z.vec[i].coeffs[j];
        }
    }
    printf("  z: %d polynomials, coeffs in [%d, %d]\n", MLDSA_L, z_min, z_max);
    printf("     (bound: |z| < %d)\n", MLDSA_GAMMA1 - MLDSA_BETA);

    /* Count hints */
    int total_hints = 0;
    for (int i = 0; i < MLDSA_OMEGA; i++) {
        if (sig->h[i] != 0 || i < sig->h[MLDSA_OMEGA]) {
            total_hints++;
        }
    }
    printf("  h: hint encoding (%d bytes)\n", H_BYTES);
}

/*
 * Simplified polynomial operations for demonstration
 * (In practice, use optimized NTT-based implementations)
 */

void poly_add(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = (a->coeffs[i] + b->coeffs[i]) % MLDSA_Q;
    }
}

void poly_sub(poly *c, const poly *a, const poly *b) {
    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = (a->coeffs[i] - b->coeffs[i] + MLDSA_Q) % MLDSA_Q;
    }
}

/* Simplified schoolbook multiplication (NOT for production!) */
void poly_pointwise_mul(poly *c, const poly *a, const poly *b) {
    int64_t temp[2 * MLDSA_N] = {0};

    /* Schoolbook multiplication */
    for (int i = 0; i < MLDSA_N; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }

    /* Reduce modulo X^N + 1 */
    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = (int32_t)((temp[i] - temp[i + MLDSA_N]) % MLDSA_Q);
        if (c->coeffs[i] < 0) c->coeffs[i] += MLDSA_Q;
    }
}

/*
 * Generate test keys (simplified - not cryptographically secure!)
 */
void generate_test_keys(uint8_t rho[32], uint8_t K[32], uint8_t tr[64],
                        polyvecl *s1, polyveck *s2, polyveck *t0,
                        poly A[MLDSA_K][MLDSA_L]) {
    /* Initialize seeds */
    for (int i = 0; i < 32; i++) {
        rho[i] = (uint8_t)(i * 0x37);
        K[i] = (uint8_t)(i * 0x5a + 0x12);
    }
    for (int i = 0; i < 64; i++) {
        tr[i] = (uint8_t)(i * 0x93 + 0x45);
    }

    /* Generate small secret vectors */
    for (int i = 0; i < MLDSA_L; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            s1->vec[i].coeffs[j] = ((i + j) % (2 * MLDSA_ETA + 1)) - MLDSA_ETA;
        }
    }
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            s2->vec[i].coeffs[j] = ((i * 3 + j) % (2 * MLDSA_ETA + 1)) - MLDSA_ETA;
        }
    }

    /* Generate t0 with small coefficients */
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            t0->vec[i].coeffs[j] = ((i * 7 + j) % (1 << MLDSA_D)) - (1 << (MLDSA_D - 1));
        }
    }

    /* Generate random-looking matrix A */
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_L; j++) {
            for (int k = 0; k < MLDSA_N; k++) {
                uint32_t seed = rho[k % 32] ^ (i * 256 + j * 16 + k);
                seed = seed * 1103515245 + 12345;
                A[i][j].coeffs[k] = seed % MLDSA_Q;
            }
        }
    }
}

/*
 * Run signing experiments
 */
void signing_experiments(void) {
    uint8_t rho[32], K[32], tr[64];
    polyvecl s1;
    polyveck s2, t0;
    poly A[MLDSA_K][MLDSA_L];
    signature sig;

    printf("=== ML-DSA Signing Experiments ===\n\n");

    /* Generate test keys */
    printf("Generating test keys...\n");
    generate_test_keys(rho, K, tr, &s1, &s2, &t0, A);

    /* Test message */
    const char *message = "This is a test message for ML-DSA signing.";

    printf("\nMessage: \"%s\"\n", message);
    printf("Message length: %zu bytes\n\n", strlen(message));

    /* Sign the message */
    int result = mldsa_sign(&sig,
                            (const uint8_t *)message, strlen(message),
                            rho, K, tr, &s1, &s2, &t0, A);

    if (result) {
        print_signature_info(&sig);

        /* Verify z norm bound */
        printf("\nVerifying signature properties:\n");
        printf("  z norm check (< %d): %s\n",
               MLDSA_GAMMA1 - MLDSA_BETA,
               polyvecl_check_norm(&sig.z, MLDSA_GAMMA1 - MLDSA_BETA) ? "PASS" : "FAIL");
    }

    /* Run multiple signatures to collect statistics */
    printf("\n=== Signing Statistics (10 signatures) ===\n");
    int total_attempts = 0;
    int max_attempts = 0;
    int min_attempts = MAX_SIGN_ATTEMPTS;

    for (int trial = 0; trial < 10; trial++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Test message number %d", trial);

        /* Count attempts for this signature */
        /* (In real implementation, track internally) */
        int attempts = 0;
        uint16_t nonce = trial * 100;

        printf("Trial %d: ", trial + 1);
        fflush(stdout);

        for (attempts = 1; attempts <= 50; attempts++) {
            polyvecl y;
            polyveck w, w1;
            poly c;
            polyvecl cs1;
            polyveck cs2, ct0, r, r0, h;
            uint8_t mu[64], ctilde[CTILDE_BYTES];

            /* Sample y and compute */
            sample_mask_vector(&y, K, mu, nonce++);
            matrix_vector_mul(&w, A, &y);
            polyveck_highbits(&w1, &w);
            hash_commitment(ctilde, mu, &w1);
            sample_in_ball(&c, ctilde);

            /* Compute z = y + c*s1 */
            polyvecl z;
            challenge_times_vecl(&cs1, &c, &s1);
            polyvecl_add(&z, &y, &cs1);

            /* Check 1 */
            if (!polyvecl_check_norm(&z, MLDSA_GAMMA1 - MLDSA_BETA)) continue;

            /* Check 2 */
            challenge_times_veck(&cs2, &c, &s2);
            polyveck_sub(&r, &w, &cs2);
            polyveck_lowbits(&r0, &r);
            if (!polyveck_check_norm(&r0, MLDSA_GAMMA2 - MLDSA_BETA)) continue;

            /* Check 3 */
            challenge_times_veck(&ct0, &c, &t0);
            if (!polyveck_check_norm(&ct0, MLDSA_GAMMA2)) continue;

            /* Check 4 */
            polyveck neg_ct0 = ct0;
            polyveck_negate(&neg_ct0);
            polyveck r_plus_ct0;
            polyveck_add(&r_plus_ct0, &r, &ct0);
            int h_count = make_hint_veck(&h, &neg_ct0, &r_plus_ct0);
            if (h_count > MLDSA_OMEGA) continue;

            /* Success! */
            break;
        }

        printf("%d attempts\n", attempts);
        total_attempts += attempts;
        if (attempts > max_attempts) max_attempts = attempts;
        if (attempts < min_attempts) min_attempts = attempts;
    }

    printf("\nStatistics:\n");
    printf("  Average attempts: %.2f\n", total_attempts / 10.0);
    printf("  Min attempts: %d\n", min_attempts);
    printf("  Max attempts: %d\n", max_attempts);
    printf("  Expected (theoretical): ~5.09 for ML-DSA-65\n");
}

int main(void) {
    signing_experiments();
    return 0;
}
