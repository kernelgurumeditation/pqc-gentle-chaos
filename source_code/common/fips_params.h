/*
 * fips_params.h — Single-source reference for the NIST PQC parameter sets.
 *
 * These are the load-bearing constants from FIPS 203 (ML-KEM), FIPS 204
 * (ML-DSA), and FIPS 205 (SLH-DSA). They are collected here so that reference
 * programs share ONE authoritative definition and so `make verify-params` can
 * check derived sizes against the published totals.
 *
 * Sources: FIPS 203, FIPS 204, FIPS 205 (final, August 2024).
 * Educational reference — not a production cryptographic header.
 */
#ifndef PQC_FIPS_PARAMS_H
#define PQC_FIPS_PARAMS_H

/* ----------------------------------------------------------------------- */
/* ML-KEM (FIPS 203) — shared ring parameters                              */
/* ----------------------------------------------------------------------- */
#define MLKEM_N            256
#define MLKEM_Q            3329
#define MLKEM_BARRETT_M    20159   /* round(2^26 / Q) for Barrett reduction */
#define MLKEM_MONT_QINV    62209   /* -Q^{-1} mod 2^16 (Montgomery)         */
#define MLKEM_MONT_R       2285    /* 2^16 mod Q                            */
#define MLKEM_ZETA         17      /* a 256th root of unity mod Q           */

/* ML-KEM-768 (NIST Category 3, ~192-bit) */
#define MLKEM768_K         3
#define MLKEM768_ETA1      2
#define MLKEM768_ETA2      2
#define MLKEM768_DU        10
#define MLKEM768_DV        4
#define MLKEM768_EK_BYTES  1184    /* encapsulation (public) key            */
#define MLKEM768_DK_BYTES  2400    /* decapsulation (secret) key            */
#define MLKEM768_CT_BYTES  1088    /* ciphertext                            */
#define MLKEM768_SS_BYTES  32      /* shared secret                         */

/* ----------------------------------------------------------------------- */
/* ML-DSA (FIPS 204)                                                        */
/* ----------------------------------------------------------------------- */
#define MLDSA_N            256
#define MLDSA_Q            8380417
#define MLDSA_D            13

/* ML-DSA-65 (NIST Category 3, ~192-bit) */
#define MLDSA65_K          6       /* rows of A / size of t, w, etc.        */
#define MLDSA65_L          5       /* cols of A / size of s1, y, z          */
#define MLDSA65_ETA        4
#define MLDSA65_TAU        49      /* # of +/-1 in challenge c              */
#define MLDSA65_BETA       196     /* TAU * ETA = 49 * 4                     */
#define MLDSA65_GAMMA1     (1 << 19)
#define MLDSA65_GAMMA2     261888  /* (Q-1)/32                              */
#define MLDSA65_OMEGA      55      /* max # of 1s in the hint               */
#define MLDSA65_CTILDE     48      /* challenge-hash bytes (lambda/4 = 192/4)*/
#define MLDSA65_T1_BITS    10
#define MLDSA65_PK_BYTES   1952    /* 32 + K*N*T1_BITS/8 = 32 + 1920        */
#define MLDSA65_SIG_BYTES  3309    /* CTILDE + L*N*20/8 + (OMEGA+K)         */

/* ----------------------------------------------------------------------- */
/* SLH-DSA (FIPS 205)                                                       */
/* ----------------------------------------------------------------------- */
/* SLH-DSA-SHA2-128f ("fast" variant, NIST Category 1) */
#define SLHDSA_128F_N      16
#define SLHDSA_128F_H      66
#define SLHDSA_128F_D      22
#define SLHDSA_128F_HP     3       /* h' = h/d                              */
#define SLHDSA_128F_A      6       /* log2 of FORS tree height              */
#define SLHDSA_128F_K      33      /* # of FORS trees                       */
#define SLHDSA_128F_W      16      /* Winternitz parameter                  */
#define SLHDSA_128F_SIG    17088   /* signature bytes                       */
#define SLHDSA_128S_SIG    7856    /* SLH-DSA-SHA2-128s ("small") signature */

/* WOTS+ derived lengths for n=32, w=16 (used in Module 7 examples): */
#define WOTS_N32_W16_LEN1  64      /* 8*n / log2(w) = 256/4                 */
#define WOTS_N32_W16_LEN2  3
#define WOTS_N32_W16_LEN   67      /* LEN1 + LEN2                           */

/* ----------------------------------------------------------------------- */
/* X-Wing hybrid KEM (X25519 + ML-KEM-768)                                 */
/* ----------------------------------------------------------------------- */
#define XWING_SK_BYTES     2432    /* 32 (X25519 sk) + 2400 (ML-KEM-768 dk) */
#define XWING_PK_BYTES     1216    /* 32 + 1184                             */
#define XWING_CT_BYTES     1120    /* 32 + 1088                             */
#define XWING_SS_BYTES     32

#endif /* PQC_FIPS_PARAMS_H */
