/*
 * ML-DSA Verification Implementation
 *
 * This implementation demonstrates the complete verification algorithm.
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

/* Number of HighBits values */
#define MLDSA_M ((MLDSA_Q - 1) / (2 * MLDSA_GAMMA2))  /* 16 */

/* Signature components */
#define CTILDE_BYTES 48
#define H_BYTES (MLDSA_OMEGA + MLDSA_K)

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
} signature;

typedef struct {
    uint8_t rho[32];
    polyveck t1;
} public_key;

/* Forward declarations */
void poly_pointwise_mul(poly *c, const poly *a, const poly *b);
void poly_add(poly *c, const poly *a, const poly *b);
void poly_sub(poly *c, const poly *a, const poly *b);

/*
 * Decompose r into (r1, r0) such that r = r1 * 2*GAMMA2 + r0
 */
void decompose(int32_t r, int32_t *r1, int32_t *r0) {
    r = r % MLDSA_Q;
    if (r < 0) r += MLDSA_Q;

    *r0 = r % (2 * MLDSA_GAMMA2);
    if (*r0 > MLDSA_GAMMA2) {
        *r0 -= 2 * MLDSA_GAMMA2;
    }

    if (r - *r0 == MLDSA_Q - 1) {
        *r1 = 0;
        *r0 -= 1;
    } else {
        *r1 = (r - *r0) / (2 * MLDSA_GAMMA2);
    }
}

/*
 * HighBits function
 */
int32_t high_bits(int32_t r) {
    int32_t r1, r0;
    decompose(r, &r1, &r0);
    return r1;
}

/*
 * LowBits function
 */
int32_t low_bits(int32_t r) {
    int32_t r1, r0;
    decompose(r, &r1, &r0);
    return r0;
}

/*
 * UseHint: recover original high bits using hint
 *
 * h: hint value (0 or 1)
 * r: value to process
 * Returns: corrected high bits
 */
int32_t use_hint(int32_t h, int32_t r) {
    int32_t r1, r0;
    decompose(r, &r1, &r0);

    if (h == 0) {
        return r1;
    }

    /* Correction needed */
    if (r0 > 0) {
        return (r1 + 1) % MLDSA_M;
    } else {
        return (r1 - 1 + MLDSA_M) % MLDSA_M;
    }
}

/*
 * Apply UseHint to entire polynomial
 */
void poly_use_hint(poly *out, const poly *h, const poly *r) {
    for (int i = 0; i < MLDSA_N; i++) {
        out->coeffs[i] = use_hint(h->coeffs[i], r->coeffs[i]);
    }
}

/*
 * Apply UseHint to vector of k polynomials
 */
void polyveck_use_hint(polyveck *out, const polyveck *h, const polyveck *r) {
    for (int i = 0; i < MLDSA_K; i++) {
        poly_use_hint(&out->vec[i], &h->vec[i], &r->vec[i]);
    }
}

/*
 * Constant-time comparison
 */
static int32_t ct_ge(int32_t a, int32_t b) {
    return (int32_t)(1 - ((uint32_t)(a - b) >> 31));
}

static int32_t ct_abs(int32_t x) {
    int32_t mask = x >> 31;
    return (x ^ mask) - mask;
}

/*
 * Check polynomial norm bound (constant-time)
 */
int poly_check_norm(const poly *p, int32_t bound) {
    int32_t reject = 0;

    for (int i = 0; i < MLDSA_N; i++) {
        int32_t coeff = p->coeffs[i];
        coeff = coeff - (ct_ge(coeff, (MLDSA_Q + 1) / 2) & MLDSA_Q);
        int32_t abs_coeff = ct_abs(coeff);
        reject |= ct_ge(abs_coeff, bound);
    }

    return reject == 0;
}

/*
 * Check l-vector norm bound
 */
int polyvecl_check_norm(const polyvecl *v, int32_t bound) {
    for (int i = 0; i < MLDSA_L; i++) {
        if (!poly_check_norm(&v->vec[i], bound)) {
            return 0;
        }
    }
    return 1;
}

/*
 * Decode hint from byte array to polynomial vector
 * Returns number of hints decoded, or -1 on error
 */
int decode_hint(polyveck *h, const uint8_t h_bytes[H_BYTES]) {
    int total = 0;

    /* Initialize h to zero */
    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            h->vec[i].coeffs[j] = 0;
        }
    }

    /* Decode hints for each polynomial */
    int pos = 0;
    for (int i = 0; i < MLDSA_K; i++) {
        int end = h_bytes[MLDSA_OMEGA + i];

        /* Validate end marker */
        if (end < pos || end > MLDSA_OMEGA) {
            return -1;  /* Invalid encoding */
        }

        /* Check positions are sorted and valid */
        int prev = -1;
        for (int j = pos; j < end; j++) {
            int idx = h_bytes[j];
            if (idx <= prev || idx >= MLDSA_N) {
                return -1;  /* Invalid or unsorted position */
            }
            h->vec[i].coeffs[idx] = 1;
            prev = idx;
            total++;
        }

        pos = end;
    }

    return total;
}

/*
 * Sample challenge polynomial from seed
 */
void sample_in_ball(poly *c, const uint8_t ctilde[CTILDE_BYTES]) {
    uint8_t buf[136];
    uint64_t signs;
    int pos;

    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = 0;
    }

    memcpy(buf, ctilde, CTILDE_BYTES);
    for (int i = CTILDE_BYTES; i < 136; i++) {
        buf[i] = (uint8_t)(i * 0x9e + ctilde[i % CTILDE_BYTES]);
    }

    signs = 0;
    for (int i = 0; i < 8; i++) {
        signs |= ((uint64_t)buf[i]) << (8 * i);
    }

    pos = 8;
    for (int i = MLDSA_N - MLDSA_TAU; i < MLDSA_N; i++) {
        int j;
        do {
            if (pos >= 136) {
                /* Real implementation per FIPS 204 §6.1: squeeze fresh SHAKE256 output.
                   Simplified: wrap buffer (demo only — not cryptographically safe) */
                pos = 0;
            }
            j = buf[pos++];
        } while (j > i);

        c->coeffs[i] = c->coeffs[j];
        c->coeffs[j] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}

/*
 * Compute transcript hash (simplified)
 */
void compute_tr(uint8_t tr[64], const public_key *pk) {
    for (int i = 0; i < 32; i++) {
        tr[i] = pk->rho[i];
    }
    for (int i = 32; i < 64; i++) {
        tr[i] = 0;
        for (int j = 0; j < MLDSA_K; j++) {
            tr[i] ^= (uint8_t)(pk->t1.vec[j].coeffs[i % MLDSA_N] & 0xFF);
        }
    }
}

/*
 * Compute message hash (simplified)
 */
void hash_message(uint8_t mu[64], const uint8_t tr[64],
                  const uint8_t *msg, size_t msglen) {
    for (int i = 0; i < 64; i++) {
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
    uint8_t temp[32];

    for (int i = 0; i < 32; i++) {
        temp[i] = mu[i] ^ mu[i + 32];
    }

    for (int k = 0; k < MLDSA_K; k++) {
        for (int j = 0; j < MLDSA_N; j += 8) {
            temp[j / 8 % 32] ^= (uint8_t)(w1->vec[k].coeffs[j] & 0xFF);
        }
    }

    memcpy(ctilde, temp, CTILDE_BYTES);
}

/*
 * Expand matrix A from seed (simplified)
 */
void expand_A(poly A[MLDSA_K][MLDSA_L], const uint8_t rho[32]) {
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
 * Matrix-vector multiplication: w = A * v
 */
void matrix_vector_mul(polyveck *w, const poly A[MLDSA_K][MLDSA_L],
                       const polyvecl *v) {
    poly temp;

    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            w->vec[i].coeffs[j] = 0;
        }

        for (int j = 0; j < MLDSA_L; j++) {
            poly_pointwise_mul(&temp, &A[i][j], &v->vec[j]);
            poly_add(&w->vec[i], &w->vec[i], &temp);
        }
    }
}

/*
 * Multiply polynomial by scalar and shift
 * out = p * 2^d
 */
void poly_shift(poly *out, const poly *p, int d) {
    int32_t shift = 1 << d;
    for (int i = 0; i < MLDSA_N; i++) {
        int64_t val = (int64_t)p->coeffs[i] * shift;
        out->coeffs[i] = (int32_t)(val % MLDSA_Q);
    }
}

/*
 * Multiply challenge by t1 and shift
 */
void challenge_times_t1_shifted(polyveck *ct, const poly *c,
                                const polyveck *t1) {
    poly t1_shifted;

    for (int i = 0; i < MLDSA_K; i++) {
        poly_shift(&t1_shifted, &t1->vec[i], MLDSA_D);
        poly_pointwise_mul(&ct->vec[i], c, &t1_shifted);
    }
}

/*
 * Vector subtraction
 */
void polyveck_sub(polyveck *c, const polyveck *a, const polyveck *b) {
    for (int i = 0; i < MLDSA_K; i++) {
        poly_sub(&c->vec[i], &a->vec[i], &b->vec[i]);
    }
}

/*
 * Compare two byte arrays (constant-time)
 */
int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/*
 * ML-DSA Verification Algorithm
 *
 * Returns: 1 if signature is valid, 0 if invalid
 */
int mldsa_verify(const public_key *pk,
                 const uint8_t *msg, size_t msglen,
                 const signature *sig) {
    poly A[MLDSA_K][MLDSA_L];
    polyveck h;          /* Decoded hint */
    poly c;              /* Challenge polynomial */
    polyveck w_prime;    /* A*z - c*t1*2^d */
    polyveck ct;         /* c * t1 * 2^d */
    polyveck Az;         /* A * z */
    polyveck w_prime_1;  /* HighBits after UseHint */
    uint8_t tr[64];      /* Public key hash */
    uint8_t mu[64];      /* Message hash */
    uint8_t ctilde_prime[CTILDE_BYTES];  /* Recomputed challenge */

    printf("=== ML-DSA Verification ===\n\n");

    /* Step 1: Check z norm bound */
    printf("Step 1: Checking z norm bound...\n");
    if (!polyvecl_check_norm(&sig->z, MLDSA_GAMMA1 - MLDSA_BETA)) {
        printf("  FAILED: ||z||_inf >= %d\n", MLDSA_GAMMA1 - MLDSA_BETA);
        return 0;
    }
    printf("  PASSED: ||z||_inf < %d\n", MLDSA_GAMMA1 - MLDSA_BETA);

    /* Step 2: Decode and check hint */
    printf("\nStep 2: Decoding hint...\n");
    int hint_count = decode_hint(&h, sig->h);
    if (hint_count < 0) {
        printf("  FAILED: Invalid hint encoding\n");
        return 0;
    }
    if (hint_count > MLDSA_OMEGA) {
        printf("  FAILED: Too many hints (%d > %d)\n", hint_count, MLDSA_OMEGA);
        return 0;
    }
    printf("  PASSED: %d hints decoded (max %d)\n", hint_count, MLDSA_OMEGA);

    /* Step 3: Expand matrix A */
    printf("\nStep 3: Expanding matrix A from rho...\n");
    expand_A(A, pk->rho);
    printf("  Done: A is %d x %d matrix of polynomials\n", MLDSA_K, MLDSA_L);

    /* Step 4: Compute transcript hash and message hash */
    printf("\nStep 4: Computing message hash...\n");
    compute_tr(tr, pk);
    hash_message(mu, tr, msg, msglen);
    printf("  mu = %02x%02x%02x%02x...%02x%02x%02x%02x\n",
           mu[0], mu[1], mu[2], mu[3], mu[60], mu[61], mu[62], mu[63]);

    /* Step 5: Reconstruct challenge polynomial */
    printf("\nStep 5: Reconstructing challenge polynomial...\n");
    sample_in_ball(&c, sig->ctilde);

    /* Count non-zeros for verification */
    int nonzeros = 0;
    for (int i = 0; i < MLDSA_N; i++) {
        if (c.coeffs[i] != 0) nonzeros++;
    }
    printf("  c has %d non-zero coefficients (expected %d)\n",
           nonzeros, MLDSA_TAU);

    /* Step 6: Compute w' = A*z - c*t1*2^d */
    printf("\nStep 6: Computing verification value w'...\n");

    /* A * z */
    matrix_vector_mul(&Az, A, &sig->z);

    /* c * t1 * 2^d */
    challenge_times_t1_shifted(&ct, &c, &pk->t1);

    /* w' = A*z - c*t1*2^d */
    polyveck_sub(&w_prime, &Az, &ct);
    printf("  w' = A*z - c*t1*2^d computed\n");

    /* Step 7: Apply UseHint to recover w1 */
    printf("\nStep 7: Applying UseHint to recover w1...\n");
    polyveck_use_hint(&w_prime_1, &h, &w_prime);
    printf("  w'1 = UseHint(h, w') computed\n");

    /* Step 8: Recompute challenge and compare */
    printf("\nStep 8: Recomputing challenge...\n");
    hash_commitment(ctilde_prime, mu, &w_prime_1);

    printf("  Original c̃:   %02x%02x%02x%02x...%02x%02x%02x%02x\n",
           sig->ctilde[0], sig->ctilde[1], sig->ctilde[2], sig->ctilde[3],
           sig->ctilde[28], sig->ctilde[29], sig->ctilde[30], sig->ctilde[31]);
    printf("  Recomputed c̃': %02x%02x%02x%02x...%02x%02x%02x%02x\n",
           ctilde_prime[0], ctilde_prime[1], ctilde_prime[2], ctilde_prime[3],
           ctilde_prime[28], ctilde_prime[29], ctilde_prime[30], ctilde_prime[31]);

    /* Final comparison */
    if (bytes_equal(sig->ctilde, ctilde_prime, CTILDE_BYTES)) {
        printf("\n=== SIGNATURE VALID ===\n");
        return 1;
    } else {
        printf("\n=== SIGNATURE INVALID ===\n");
        return 0;
    }
}

/*
 * Polynomial arithmetic (simplified implementations)
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

void poly_pointwise_mul(poly *c, const poly *a, const poly *b) {
    int64_t temp[2 * MLDSA_N] = {0};

    for (int i = 0; i < MLDSA_N; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            temp[i + j] += (int64_t)a->coeffs[i] * b->coeffs[j];
        }
    }

    for (int i = 0; i < MLDSA_N; i++) {
        c->coeffs[i] = (int32_t)((temp[i] - temp[i + MLDSA_N]) % MLDSA_Q);
        if (c->coeffs[i] < 0) c->coeffs[i] += MLDSA_Q;
    }
}

/*
 * Create test public key and signature for demonstration
 */
void create_test_data(public_key *pk, signature *sig) {
    /* Initialize public key */
    for (int i = 0; i < 32; i++) {
        pk->rho[i] = (uint8_t)(i * 0x37);
    }

    for (int i = 0; i < MLDSA_K; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            pk->t1.vec[i].coeffs[j] = (i * 256 + j) % MLDSA_M;
        }
    }

    /* Initialize signature with valid-looking data */
    for (int i = 0; i < CTILDE_BYTES; i++) {
        sig->ctilde[i] = (uint8_t)(i * 0x9e);
    }

    /* z with coefficients in valid range */
    for (int i = 0; i < MLDSA_L; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            /* Keep well within bounds */
            sig->z.vec[i].coeffs[j] = ((i + j) * 1000) % (MLDSA_GAMMA1 / 2);
            if ((i + j) % 2) {
                sig->z.vec[i].coeffs[j] = -sig->z.vec[i].coeffs[j];
            }
        }
    }

    /* Create hint with few entries */
    memset(sig->h, 0, H_BYTES);

    /* Place a few hints */
    sig->h[0] = 10;   /* Position 10 in poly 0 */
    sig->h[1] = 50;   /* Position 50 in poly 0 */
    sig->h[MLDSA_OMEGA + 0] = 2;  /* End marker for poly 0 */

    sig->h[2] = 100;  /* Position 100 in poly 1 */
    sig->h[MLDSA_OMEGA + 1] = 3;  /* End marker for poly 1 */

    /* Remaining polynomials have no hints */
    for (int i = 2; i < MLDSA_K; i++) {
        sig->h[MLDSA_OMEGA + i] = 3;  /* All end at same position */
    }
}

/*
 * Demonstrate verification with test data
 */
void verification_demo(void) {
    public_key pk;
    signature sig;
    const char *message = "Test message for verification";

    printf("Creating test data...\n\n");
    create_test_data(&pk, &sig);

    /* This will fail because our test signature isn't actually valid
       (we didn't sign it properly), but it demonstrates the algorithm */
    mldsa_verify(&pk, (const uint8_t *)message, strlen(message), &sig);
}

/*
 * Demonstrate UseHint behavior
 */
void use_hint_demo(void) {
    printf("\n=== UseHint Demonstration ===\n\n");

    /* Test cases showing UseHint behavior */
    struct {
        int32_t h;
        int32_t r;
        const char *description;
    } tests[] = {
        {0, 261888, "No correction, value at boundary"},
        {0, 500000, "No correction, middle value"},
        {1, 523779, "Correction needed, positive low bits"},
        {1, 524000, "Correction needed, negative low bits"},
        {0, 0, "No correction, zero"},
    };

    printf("γ₂ = %d, 2γ₂ = %d, m = %d\n\n", MLDSA_GAMMA2, 2 * MLDSA_GAMMA2, MLDSA_M);

    for (int i = 0; i < 5; i++) {
        int32_t r1 = high_bits(tests[i].r);
        int32_t r0 = low_bits(tests[i].r);
        int32_t corrected = use_hint(tests[i].h, tests[i].r);

        printf("Test %d: %s\n", i + 1, tests[i].description);
        printf("  Input: h=%d, r=%d\n", tests[i].h, tests[i].r);
        printf("  HighBits(r) = %d, LowBits(r) = %d\n", r1, r0);
        printf("  UseHint(h, r) = %d\n", corrected);
        if (tests[i].h == 1) {
            printf("  Correction: %d → %d (%+d)\n",
                   r1, corrected, corrected - r1);
        }
        printf("\n");
    }
}

int main(void) {
    use_hint_demo();
    verification_demo();
    return 0;
}
