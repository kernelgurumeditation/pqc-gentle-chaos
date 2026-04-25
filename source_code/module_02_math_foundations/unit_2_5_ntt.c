// ntt.c - Number Theoretic Transform for ML-KEM
// Source: Module 2, Unit 2.5 - Number Theoretic Transform (NTT)
// Compile: gcc -O2 -o ntt ntt.c

#include <stdint.h>
#include <stdio.h>

#define N 256
#define Q 3329

// Precomputed: ζ^brv(i) mod Q for i = 1 to 127
// These are the twiddle factors used in ML-KEM
static const int16_t zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182,
    962, 2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199,
    2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015,
    2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
    2476, 3239, 3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604,
    448, 2264, 677, 2054, 2226, 430, 555, 843, 2078, 871, 1550, 105,
    422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193, 1218, 1994,
    2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
    3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

// Montgomery constant: R = 2^16 mod Q
#define MONT_R 2285  // 2^16 mod 3329

// Reduce to [0, Q-1] using Barrett
static inline int16_t barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + Q / 2) / Q;
    t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= Q;
    return a - t;
}

// Montgomery reduction
static inline int16_t montgomery_reduce(int32_t a) {
    int16_t t;
    t = (int16_t)a * (-3327);  // Q^{-1} mod 2^16 = -3327 mod 2^16
    t = (a - (int32_t)t * Q) >> 16;
    return t;
}

// Multiply two elements in Montgomery form
static inline int16_t fqmul(int16_t a, int16_t b) {
    return montgomery_reduce((int32_t)a * b);
}

// Forward NTT
void ntt(int16_t poly[N]) {
    unsigned int k = 1;
    for (unsigned int len = 128; len >= 2; len >>= 1) {
        for (unsigned int start = 0; start < N; start += 2 * len) {
            int16_t zeta = zetas[k++];
            for (unsigned int j = start; j < start + len; j++) {
                int16_t t = fqmul(zeta, poly[j + len]);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
        }
    }
}

// Inverse NTT
void invntt(int16_t poly[N]) {
    unsigned int k = 127;
    for (unsigned int len = 2; len <= 128; len <<= 1) {
        for (unsigned int start = 0; start < N; start += 2 * len) {
            int16_t zeta = zetas[k--];
            for (unsigned int j = start; j < start + len; j++) {
                int16_t t = poly[j];
                poly[j] = barrett_reduce(t + poly[j + len]);
                poly[j + len] = fqmul(zeta, poly[j + len] - t);
            }
        }
    }
    // Multiply by 128^{-1} = 3303 mod Q (in Montgomery form: 1441)
    for (unsigned int i = 0; i < N; i++) {
        poly[i] = fqmul(poly[i], 1441);
    }
}

// Basemul: multiply two degree-1 polynomials mod X^2 - zeta
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}

// Test NTT round-trip
int main(void) {
    int16_t a[N], b[N];

    // Initialize with small test values
    for (int i = 0; i < N; i++) {
        a[i] = i % 10;
        b[i] = a[i];  // Copy for comparison
    }

    printf("NTT Test:\n");
    printf("Original a[0..4]: %d %d %d %d %d\n", a[0], a[1], a[2], a[3], a[4]);

    ntt(a);
    printf("After NTT a[0..4]: %d %d %d %d %d\n", a[0], a[1], a[2], a[3], a[4]);

    invntt(a);
    printf("After INTT a[0..4]: %d %d %d %d %d\n",
           barrett_reduce(a[0]), barrett_reduce(a[1]),
           barrett_reduce(a[2]), barrett_reduce(a[3]), barrett_reduce(a[4]));

    // Verify round-trip
    int errors = 0;
    for (int i = 0; i < N; i++) {
        int16_t recovered = barrett_reduce(a[i]);
        if (recovered < 0) recovered += Q;
        if (recovered != b[i]) {
            errors++;
            if (errors < 5) {
                printf("Mismatch at %d: got %d, expected %d\n", i, recovered, b[i]);
            }
        }
    }
    printf("Round-trip errors: %d\n", errors);

    return 0;
}
