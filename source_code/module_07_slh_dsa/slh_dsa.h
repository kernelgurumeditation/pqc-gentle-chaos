/* slh_dsa.h - SLH-DSA-SHA2-128f implementation */

#ifndef SLH_DSA_H
#define SLH_DSA_H

#include <stdint.h>
#include <stddef.h>

/*
 * SLH-DSA-SHA2-128f Parameters (FIPS 205)
 */
#define SLH_N              16    /* Hash output size, security parameter */
#define SLH_H              66    /* Total hypertree height */
#define SLH_D              22    /* Number of hypertree layers */
#define SLH_HP             3     /* Height per layer (h/d) */
#define SLH_A              6     /* FORS tree height */
#define SLH_K              33    /* Number of FORS trees */
#define SLH_W              16    /* Winternitz parameter */
#define SLH_LEN1           32    /* ceil(8*n / log2(w)) */
#define SLH_LEN2           3     /* Checksum length */
#define SLH_LEN            35    /* Total WOTS+ length */

/* Derived sizes */
#define SLH_WOTS_BYTES     (SLH_LEN * SLH_N)           /* 560 */
#define SLH_FORS_MSG_BYTES ((SLH_K * SLH_A + 7) / 8)   /* 25 */
#define SLH_TREE_BITS      (SLH_H - SLH_HP)            /* 63 */
#define SLH_LEAF_BITS      SLH_HP                      /* 3 */

/* Signature size */
#define SLH_FORS_SIG_BYTES (SLH_K * (1 + SLH_A) * SLH_N)  /* 3696 */
#define SLH_XMSS_SIG_BYTES ((SLH_LEN + SLH_HP) * SLH_N)   /* 608 */
#define SLH_HT_SIG_BYTES   (SLH_D * SLH_XMSS_SIG_BYTES)   /* 13376 */
#define SLH_SIG_BYTES      (SLH_N + SLH_FORS_SIG_BYTES + SLH_HT_SIG_BYTES)

/* Key sizes */
#define SLH_SK_BYTES       (4 * SLH_N)   /* 64 bytes */
#define SLH_PK_BYTES       (2 * SLH_N)   /* 32 bytes */

/*
 * Address structure (32 bytes)
 */
typedef struct {
    uint8_t bytes[32];
} slh_addr_t;

/* Address field accessors */
#define ADDR_LAYER(a)       ((a)->bytes[0])
#define ADDR_TREE(a)        (&(a)->bytes[4])   /* 8 bytes */
#define ADDR_TYPE(a)        ((a)->bytes[12])
#define ADDR_KEYPAIR(a)     (&(a)->bytes[16])  /* 4 bytes */
#define ADDR_CHAIN(a)       (&(a)->bytes[20])  /* 4 bytes */
#define ADDR_HASH(a)        (&(a)->bytes[24])  /* 4 bytes */
#define ADDR_TREE_HEIGHT(a) (&(a)->bytes[24])  /* 4 bytes (overlay) */
#define ADDR_TREE_INDEX(a)  (&(a)->bytes[28])  /* 4 bytes */

/* Address types */
#define SLH_ADDR_WOTS_HASH   0
#define SLH_ADDR_WOTS_PK     1
#define SLH_ADDR_TREE        2
#define SLH_ADDR_FORS_TREE   3
#define SLH_ADDR_FORS_ROOTS  4
#define SLH_ADDR_WOTS_PRF    5
#define SLH_ADDR_FORS_PRF    6

/*
 * Key structures
 */
typedef struct {
    uint8_t seed[SLH_N];      /* SK.seed - secret seed */
    uint8_t prf[SLH_N];       /* SK.prf - PRF key */
    uint8_t pub_seed[SLH_N];  /* PK.seed - public seed */
    uint8_t pub_root[SLH_N];  /* PK.root - hypertree root */
} slh_secret_key_t;

typedef struct {
    uint8_t seed[SLH_N];      /* PK.seed - public seed */
    uint8_t root[SLH_N];      /* PK.root - hypertree root */
} slh_public_key_t;

/*
 * API functions
 */

/* Key generation */
int slh_keygen(slh_secret_key_t *sk, slh_public_key_t *pk);

/* Signing */
int slh_sign(uint8_t *sig, size_t *sig_len,
             const uint8_t *msg, size_t msg_len,
             const slh_secret_key_t *sk);

/* Verification */
int slh_verify(const uint8_t *sig, size_t sig_len,
               const uint8_t *msg, size_t msg_len,
               const slh_public_key_t *pk);

#endif /* SLH_DSA_H */
