/*
 * ML-DSA Encoding/Decoding Implementation
 *
 * Demonstrates efficient compression of signature components.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ML-DSA-65 parameters */
#define N 256
#define Q 8380417
#define K 6
#define L 5
#define D 13
#define ETA 4
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q - 1) / 32)
#define OMEGA 55
#define TAU 49
#define BETA (TAU * ETA)

/* Encoding sizes */
#define Z_BITS 20           /* bits per z coefficient */
#define T1_BITS 10          /* bits per t1 coefficient */
#define T0_BITS D           /* bits per t0 coefficient */
#define ETA_BITS 4          /* bits per s coefficient */

/* Computed sizes */
#define Z_BYTES (L * N * Z_BITS / 8)          /* 3200 */
#define T1_BYTES (K * N * T1_BITS / 8)        /* 1920 */
#define T0_BYTES (K * N * T0_BITS / 8)        /* 2496 */
#define S1_BYTES (L * N * ETA_BITS / 8)       /* 640 */
#define S2_BYTES (K * N * ETA_BITS / 8)       /* 768 */
#define H_BYTES (OMEGA + K)                   /* 61 */
#define CTILDE_BYTES 48

/* Total sizes */
#define PK_BYTES (32 + T1_BYTES)              /* 1952 */
#define SK_BYTES (32 + 32 + 64 + S1_BYTES + S2_BYTES + T0_BYTES)  /* 4032 */
#define SIG_BYTES (CTILDE_BYTES + Z_BYTES + H_BYTES)  /* 3309 */

typedef struct {
    int32_t coeffs[N];
} poly;

typedef struct {
    poly vec[K];
} polyveck;

typedef struct {
    poly vec[L];
} polyvecl;

/*
 * ========== Hint Encoding/Decoding ==========
 */

/*
 * Encode hints from polynomial vector to byte array
 * Returns number of hints, or -1 on error (too many hints)
 */
int encode_hints(uint8_t h_bytes[H_BYTES], const polyveck *h) {
    int idx = 0;

    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            if (h->vec[i].coeffs[j] == 1) {
                if (idx >= OMEGA) {
                    return -1;  /* Too many hints */
                }
                h_bytes[idx++] = (uint8_t)j;
            }
        }
        h_bytes[OMEGA + i] = (uint8_t)idx;
    }

    /* Zero-fill remaining positions */
    while (idx < OMEGA) {
        h_bytes[idx++] = 0;
    }

    return h_bytes[OMEGA + K - 1];  /* Return total hint count */
}

/*
 * Decode hints from byte array to polynomial vector
 * Returns number of hints, or -1 on error
 */
int decode_hints(polyveck *h, const uint8_t h_bytes[H_BYTES]) {
    int pos = 0;
    int total = 0;

    /* Initialize to zero */
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            h->vec[i].coeffs[j] = 0;
        }
    }

    for (int i = 0; i < K; i++) {
        int end = h_bytes[OMEGA + i];

        /* Validate end marker */
        if (end < pos || end > OMEGA) {
            return -1;
        }

        /* Decode positions for this polynomial */
        int prev = -1;
        for (int j = pos; j < end; j++) {
            int idx = h_bytes[j];

            /* Positions must be strictly increasing */
            if (idx <= prev || idx >= N) {
                return -1;
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
 * ========== z Encoding (20-bit coefficients) ==========
 */

/*
 * Encode z vector (5 polynomials, 20 bits per coefficient)
 * Total: 5 * 256 * 20 / 8 = 3200 bytes
 */
void encode_z(uint8_t out[Z_BYTES], const polyvecl *z) {
    int byte_idx = 0;

    for (int i = 0; i < L; i++) {
        for (int j = 0; j < N; j += 4) {
            /* Get 4 coefficients and shift to unsigned */
            uint32_t c0 = (GAMMA1 - 1) - z->vec[i].coeffs[j];
            uint32_t c1 = (GAMMA1 - 1) - z->vec[i].coeffs[j + 1];
            uint32_t c2 = (GAMMA1 - 1) - z->vec[i].coeffs[j + 2];
            uint32_t c3 = (GAMMA1 - 1) - z->vec[i].coeffs[j + 3];

            /* Pack 4 x 20-bit values into 10 bytes */
            out[byte_idx++] = c0 & 0xFF;
            out[byte_idx++] = (c0 >> 8) & 0xFF;
            out[byte_idx++] = ((c0 >> 16) & 0x0F) | ((c1 & 0x0F) << 4);
            out[byte_idx++] = (c1 >> 4) & 0xFF;
            out[byte_idx++] = (c1 >> 12) & 0xFF;
            out[byte_idx++] = c2 & 0xFF;
            out[byte_idx++] = (c2 >> 8) & 0xFF;
            out[byte_idx++] = ((c2 >> 16) & 0x0F) | ((c3 & 0x0F) << 4);
            out[byte_idx++] = (c3 >> 4) & 0xFF;
            out[byte_idx++] = (c3 >> 12) & 0xFF;
        }
    }
}

/*
 * Decode z vector from byte array
 */
void decode_z(polyvecl *z, const uint8_t in[Z_BYTES]) {
    int byte_idx = 0;

    for (int i = 0; i < L; i++) {
        for (int j = 0; j < N; j += 4) {
            /* Unpack 10 bytes to 4 x 20-bit values */
            uint32_t c0 = in[byte_idx] |
                         ((uint32_t)in[byte_idx + 1] << 8) |
                         (((uint32_t)in[byte_idx + 2] & 0x0F) << 16);

            uint32_t c1 = ((uint32_t)in[byte_idx + 2] >> 4) |
                         ((uint32_t)in[byte_idx + 3] << 4) |
                         ((uint32_t)in[byte_idx + 4] << 12);

            uint32_t c2 = in[byte_idx + 5] |
                         ((uint32_t)in[byte_idx + 6] << 8) |
                         (((uint32_t)in[byte_idx + 7] & 0x0F) << 16);

            uint32_t c3 = ((uint32_t)in[byte_idx + 7] >> 4) |
                         ((uint32_t)in[byte_idx + 8] << 4) |
                         ((uint32_t)in[byte_idx + 9] << 12);

            byte_idx += 10;

            /* Shift back to signed */
            z->vec[i].coeffs[j]     = (GAMMA1 - 1) - (int32_t)c0;
            z->vec[i].coeffs[j + 1] = (GAMMA1 - 1) - (int32_t)c1;
            z->vec[i].coeffs[j + 2] = (GAMMA1 - 1) - (int32_t)c2;
            z->vec[i].coeffs[j + 3] = (GAMMA1 - 1) - (int32_t)c3;
        }
    }
}

/*
 * ========== t₁ Encoding (10-bit coefficients) ==========
 * t1 = t >> d where d=13, so t1 ∈ [0, (q-1)>>13] = [0, 1022].
 * This requires 10 bits per coefficient. We pack 4 coefficients
 * into 5 bytes (40 bits = 4 × 10 bits).
 */

/*
 * Encode t1 vector (6 polynomials, 10 bits per coefficient)
 * Output: K * N * 10 / 8 = T1_BYTES bytes
 */
void encode_t1(uint8_t out[T1_BYTES], const polyveck *t1) {
    int byte_idx = 0;

    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j += 4) {
            /* Pack 4 × 10-bit values into 5 bytes */
            uint16_t c0 = t1->vec[i].coeffs[j]     & 0x3FF;
            uint16_t c1 = t1->vec[i].coeffs[j + 1] & 0x3FF;
            uint16_t c2 = t1->vec[i].coeffs[j + 2] & 0x3FF;
            uint16_t c3 = t1->vec[i].coeffs[j + 3] & 0x3FF;

            out[byte_idx]     =  c0 & 0xFF;                        /* bits 0-7 of c0 */
            out[byte_idx + 1] = (c0 >> 8) | ((c1 & 0x3F) << 2);   /* bits 8-9 of c0, bits 0-5 of c1 */
            out[byte_idx + 2] = (c1 >> 6) | ((c2 & 0x0F) << 4);   /* bits 6-9 of c1, bits 0-3 of c2 */
            out[byte_idx + 3] = (c2 >> 4) | ((c3 & 0x03) << 6);   /* bits 4-9 of c2, bits 0-1 of c3 */
            out[byte_idx + 4] = (c3 >> 2);                         /* bits 2-9 of c3 */
            byte_idx += 5;
        }
    }
}

/*
 * Decode t1 vector from byte array (10 bits per coefficient)
 */
void decode_t1(polyveck *t1, const uint8_t in[T1_BYTES]) {
    int byte_idx = 0;

    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j += 4) {
            /* Unpack 4 × 10-bit values from 5 bytes */
            t1->vec[i].coeffs[j]     =  (uint16_t)in[byte_idx]
                                       | (((uint16_t)in[byte_idx + 1] & 0x03) << 8);
            t1->vec[i].coeffs[j + 1] = ((uint16_t)in[byte_idx + 1] >> 2)
                                       | (((uint16_t)in[byte_idx + 2] & 0x0F) << 6);
            t1->vec[i].coeffs[j + 2] = ((uint16_t)in[byte_idx + 2] >> 4)
                                       | (((uint16_t)in[byte_idx + 3] & 0x3F) << 4);
            t1->vec[i].coeffs[j + 3] = ((uint16_t)in[byte_idx + 3] >> 6)
                                       | (((uint16_t)in[byte_idx + 4]) << 2);
            byte_idx += 5;
        }
    }
}

/*
 * ========== t₀ Encoding (13-bit coefficients) ==========
 */

/*
 * Encode t0 vector (6 polynomials, 13 bits per coefficient)
 * 8 coefficients = 104 bits = 13 bytes
 */
void encode_t0(uint8_t out[T0_BYTES], const polyveck *t0) {
    int byte_idx = 0;

    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j += 8) {
            /* Shift to unsigned [0, 2^13 - 1] */
            uint32_t c[8];
            for (int m = 0; m < 8; m++) {
                c[m] = (1 << (D - 1)) - t0->vec[i].coeffs[j + m];
            }

            /* Pack 8 x 13-bit values into 13 bytes */
            out[byte_idx++] = c[0] & 0xFF;
            out[byte_idx++] = ((c[0] >> 8) & 0x1F) | ((c[1] & 0x07) << 5);
            out[byte_idx++] = (c[1] >> 3) & 0xFF;
            out[byte_idx++] = ((c[1] >> 11) & 0x03) | ((c[2] & 0x3F) << 2);
            out[byte_idx++] = ((c[2] >> 6) & 0x7F) | ((c[3] & 0x01) << 7);
            out[byte_idx++] = (c[3] >> 1) & 0xFF;
            out[byte_idx++] = ((c[3] >> 9) & 0x0F) | ((c[4] & 0x0F) << 4);
            out[byte_idx++] = (c[4] >> 4) & 0xFF;
            out[byte_idx++] = ((c[4] >> 12) & 0x01) | ((c[5] & 0x7F) << 1);
            out[byte_idx++] = ((c[5] >> 7) & 0x3F) | ((c[6] & 0x03) << 6);
            out[byte_idx++] = (c[6] >> 2) & 0xFF;
            out[byte_idx++] = ((c[6] >> 10) & 0x07) | ((c[7] & 0x1F) << 3);
            out[byte_idx++] = (c[7] >> 5) & 0xFF;
        }
    }
}

/*
 * Decode t0 vector from byte array
 */
void decode_t0(polyveck *t0, const uint8_t in[T0_BYTES]) {
    int byte_idx = 0;

    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j += 8) {
            /* Unpack 13 bytes to 8 x 13-bit values */
            uint32_t c[8];

            c[0] = in[byte_idx] | ((uint32_t)(in[byte_idx + 1] & 0x1F) << 8);
            c[1] = (in[byte_idx + 1] >> 5) | ((uint32_t)in[byte_idx + 2] << 3) |
                   ((uint32_t)(in[byte_idx + 3] & 0x03) << 11);
            c[2] = (in[byte_idx + 3] >> 2) | ((uint32_t)(in[byte_idx + 4] & 0x7F) << 6);
            c[3] = (in[byte_idx + 4] >> 7) | ((uint32_t)in[byte_idx + 5] << 1) |
                   ((uint32_t)(in[byte_idx + 6] & 0x0F) << 9);
            c[4] = (in[byte_idx + 6] >> 4) | ((uint32_t)in[byte_idx + 7] << 4) |
                   ((uint32_t)(in[byte_idx + 8] & 0x01) << 12);
            c[5] = (in[byte_idx + 8] >> 1) | ((uint32_t)(in[byte_idx + 9] & 0x3F) << 7);
            c[6] = (in[byte_idx + 9] >> 6) | ((uint32_t)in[byte_idx + 10] << 2) |
                   ((uint32_t)(in[byte_idx + 11] & 0x07) << 10);
            c[7] = (in[byte_idx + 11] >> 3) | ((uint32_t)in[byte_idx + 12] << 5);

            byte_idx += 13;

            /* Shift back to signed */
            for (int m = 0; m < 8; m++) {
                t0->vec[i].coeffs[j + m] = (1 << (D - 1)) - (int32_t)c[m];
            }
        }
    }
}

/*
 * ========== η-bounded secret encoding (4-bit) ==========
 */

/*
 * Encode η-bounded polynomial (4 bits per coefficient for η=4)
 */
void encode_eta(uint8_t *out, const poly *p, int eta) {
    for (int j = 0; j < N; j += 2) {
        /* Shift to unsigned [0, 2η] */
        uint8_t c0 = eta - p->coeffs[j];
        uint8_t c1 = eta - p->coeffs[j + 1];
        *out++ = (c0 & 0x0F) | ((c1 & 0x0F) << 4);
    }
}

/*
 * Decode η-bounded polynomial
 */
void decode_eta(poly *p, const uint8_t *in, int eta) {
    for (int j = 0; j < N; j += 2) {
        p->coeffs[j]     = eta - (in[j/2] & 0x0F);
        p->coeffs[j + 1] = eta - ((in[j/2] >> 4) & 0x0F);
    }
}

/*
 * ========== Full Key/Signature Encoding ==========
 */

/*
 * Encode full public key
 */
void encode_pk(uint8_t pk_bytes[PK_BYTES],
               const uint8_t rho[32],
               const polyveck *t1) {
    memcpy(pk_bytes, rho, 32);
    encode_t1(pk_bytes + 32, t1);
}

/*
 * Decode full public key
 */
void decode_pk(uint8_t rho[32], polyveck *t1,
               const uint8_t pk_bytes[PK_BYTES]) {
    memcpy(rho, pk_bytes, 32);
    decode_t1(t1, pk_bytes + 32);
}

/*
 * Encode full signature
 */
int encode_sig(uint8_t sig_bytes[SIG_BYTES],
               const uint8_t ctilde[CTILDE_BYTES],
               const polyvecl *z,
               const polyveck *h) {
    memcpy(sig_bytes, ctilde, CTILDE_BYTES);
    encode_z(sig_bytes + CTILDE_BYTES, z);

    int hint_count = encode_hints(sig_bytes + CTILDE_BYTES + Z_BYTES, h);
    return hint_count;
}

/*
 * Decode full signature
 */
int decode_sig(uint8_t ctilde[CTILDE_BYTES],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig_bytes[SIG_BYTES]) {
    memcpy(ctilde, sig_bytes, CTILDE_BYTES);
    decode_z(z, sig_bytes + CTILDE_BYTES);

    int hint_count = decode_hints(h, sig_bytes + CTILDE_BYTES + Z_BYTES);
    return hint_count;
}

/*
 * ========== Test/Demo Functions ==========
 */

void test_z_encoding(void) {
    printf("=== Testing z Encoding (20-bit) ===\n\n");

    polyvecl z_orig, z_decoded;
    uint8_t z_bytes[Z_BYTES];

    /* Create test z with values in valid range */
    for (int i = 0; i < L; i++) {
        for (int j = 0; j < N; j++) {
            /* Values in [-(GAMMA1-BETA-1), GAMMA1-BETA-1] */
            int32_t val = ((i * N + j) * 12345) % (GAMMA1 - BETA - 1);
            if ((i + j) % 2) val = -val;
            z_orig.vec[i].coeffs[j] = val;
        }
    }

    /* Encode */
    encode_z(z_bytes, &z_orig);
    printf("Encoded z: %d bytes\n", Z_BYTES);
    printf("First 20 bytes: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", z_bytes[i]);
    }
    printf("...\n");

    /* Decode */
    decode_z(&z_decoded, z_bytes);

    /* Verify */
    int errors = 0;
    for (int i = 0; i < L; i++) {
        for (int j = 0; j < N; j++) {
            if (z_orig.vec[i].coeffs[j] != z_decoded.vec[i].coeffs[j]) {
                errors++;
            }
        }
    }
    printf("Verification: %s (%d errors)\n\n",
           errors == 0 ? "PASS" : "FAIL", errors);

    /* Show some values */
    printf("Sample values:\n");
    for (int i = 0; i < 5; i++) {
        printf("  z[0][%d]: original=%d, decoded=%d\n",
               i, z_orig.vec[0].coeffs[i], z_decoded.vec[0].coeffs[i]);
    }
    printf("\n");
}

void test_hint_encoding(void) {
    printf("=== Testing Hint Encoding ===\n\n");

    polyveck h_orig, h_decoded;
    uint8_t h_bytes[H_BYTES];

    /* Initialize to zero */
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            h_orig.vec[i].coeffs[j] = 0;
        }
    }

    /* Set some hints */
    h_orig.vec[0].coeffs[10] = 1;
    h_orig.vec[0].coeffs[50] = 1;
    h_orig.vec[0].coeffs[120] = 1;
    h_orig.vec[1].coeffs[45] = 1;
    h_orig.vec[3].coeffs[77] = 1;
    h_orig.vec[3].coeffs[200] = 1;
    h_orig.vec[4].coeffs[15] = 1;

    /* Encode */
    int hint_count = encode_hints(h_bytes, &h_orig);
    printf("Encoded %d hints into %d bytes\n", hint_count, H_BYTES);

    printf("Position bytes: ");
    for (int i = 0; i < 10; i++) {
        printf("%d ", h_bytes[i]);
    }
    printf("...\n");

    printf("End markers: ");
    for (int i = 0; i < K; i++) {
        printf("%d ", h_bytes[OMEGA + i]);
    }
    printf("\n");

    /* Decode */
    int decoded_count = decode_hints(&h_decoded, h_bytes);
    printf("Decoded %d hints\n", decoded_count);

    /* Verify */
    int errors = 0;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            if (h_orig.vec[i].coeffs[j] != h_decoded.vec[i].coeffs[j]) {
                errors++;
            }
        }
    }
    printf("Verification: %s (%d errors)\n\n",
           errors == 0 ? "PASS" : "FAIL", errors);
}

void test_t1_encoding(void) {
    printf("=== Testing t₁ Encoding (10-bit) ===\n\n");

    polyveck t1_orig, t1_decoded;
    uint8_t t1_bytes[T1_BYTES];

    /* Create test t1 with realistic values in [0, 1022].
     * t1 = t >> d so coefficients span the full 10-bit range. */
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            t1_orig.vec[i].coeffs[j] = ((i * N + j) * 7) % 1023;
        }
    }

    /* Encode */
    encode_t1(t1_bytes, &t1_orig);
    printf("Encoded t₁: %d bytes\n", T1_BYTES);

    /* Decode */
    decode_t1(&t1_decoded, t1_bytes);

    /* Verify */
    int errors = 0;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N; j++) {
            if (t1_orig.vec[i].coeffs[j] != t1_decoded.vec[i].coeffs[j]) {
                errors++;
            }
        }
    }
    printf("Verification: %s (%d errors)\n\n",
           errors == 0 ? "PASS" : "FAIL", errors);
}

void print_size_summary(void) {
    printf("=== ML-DSA-65 Size Summary ===\n\n");

    printf("Public Key Components:\n");
    printf("  ρ (seed):          32 bytes\n");
    printf("  t₁ (high bits):    %d bytes\n", T1_BYTES);
    printf("  Total PK:          %d bytes\n\n", PK_BYTES);

    printf("Secret Key Components:\n");
    printf("  ρ (seed):          32 bytes\n");
    printf("  K (signing key):   32 bytes\n");
    printf("  tr (pk hash):      64 bytes\n");
    printf("  s₁:                %d bytes\n", S1_BYTES);
    printf("  s₂:                %d bytes\n", S2_BYTES);
    printf("  t₀ (low bits):     %d bytes\n", T0_BYTES);
    printf("  Total SK:          %d bytes\n\n", SK_BYTES);

    printf("Signature Components:\n");
    printf("  c̃ (challenge):     %d bytes\n", CTILDE_BYTES);
    printf("  z (response):      %d bytes\n", Z_BYTES);
    printf("  h (hints):         %d bytes\n", H_BYTES);
    printf("  Total Signature:   %d bytes\n\n", SIG_BYTES);

    printf("Comparison:\n");
    printf("  RSA-2048:  pk=256, sig=256 (total 512)\n");
    printf("  ECDSA-256: pk=64, sig=64 (total 128)\n");
    printf("  ML-DSA-65: pk=%d, sig=%d (total %d)\n",
           PK_BYTES, SIG_BYTES, PK_BYTES + SIG_BYTES);
}

int main(void) {
    test_z_encoding();
    test_hint_encoding();
    test_t1_encoding();
    print_size_summary();
    return 0;
}
