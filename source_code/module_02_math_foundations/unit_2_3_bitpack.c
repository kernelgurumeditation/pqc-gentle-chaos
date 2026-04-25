// bitpack.c - Bit packing for compressed coefficients
// Source: Module 2, Unit 2.3 - Polynomial Ring Arithmetic in Depth
// Compile: gcc -O2 -o bitpack bitpack.c

#include <stdint.h>
#include <stdio.h>

#define N 256

// Pack 256 10-bit values into 320 bytes
// 4 coefficients -> 5 bytes
void pack_10bit(uint8_t *out, const uint16_t *in) {
    for (int i = 0; i < N / 4; i++) {
        uint16_t c0 = in[4*i + 0];
        uint16_t c1 = in[4*i + 1];
        uint16_t c2 = in[4*i + 2];
        uint16_t c3 = in[4*i + 3];

        out[5*i + 0] = c0 & 0xFF;
        out[5*i + 1] = ((c0 >> 8) & 0x03) | ((c1 & 0x3F) << 2);
        out[5*i + 2] = ((c1 >> 6) & 0x0F) | ((c2 & 0x0F) << 4);
        out[5*i + 3] = ((c2 >> 4) & 0x3F) | ((c3 & 0x03) << 6);
        out[5*i + 4] = (c3 >> 2) & 0xFF;
    }
}

// Unpack 320 bytes into 256 10-bit values
void unpack_10bit(uint16_t *out, const uint8_t *in) {
    for (int i = 0; i < N / 4; i++) {
        out[4*i + 0] = (in[5*i + 0]) | ((uint16_t)(in[5*i + 1] & 0x03) << 8);
        out[4*i + 1] = (in[5*i + 1] >> 2) | ((uint16_t)(in[5*i + 2] & 0x0F) << 6);
        out[4*i + 2] = (in[5*i + 2] >> 4) | ((uint16_t)(in[5*i + 3] & 0x3F) << 4);
        out[4*i + 3] = (in[5*i + 3] >> 6) | ((uint16_t)(in[5*i + 4]) << 2);
    }
}

int main(void) {
    uint16_t original[N];
    uint8_t packed[320];
    uint16_t unpacked[N];

    // Fill with test values
    for (int i = 0; i < N; i++) {
        original[i] = i * 4;  // Values 0, 4, 8, ..., 1020 (all < 1024 = 2^10)
    }

    pack_10bit(packed, original);
    unpack_10bit(unpacked, packed);

    // Verify
    int errors = 0;
    for (int i = 0; i < N; i++) {
        if (original[i] != unpacked[i]) {
            printf("ERROR at %d: %d != %d\n", i, original[i], unpacked[i]);
            errors++;
        }
    }

    printf("Bit packing test (10-bit): %d errors\n", errors);
    printf("Original size: %zu bytes\n", N * sizeof(uint16_t));
    printf("Packed size: %zu bytes\n", sizeof(packed));
    printf("Compression ratio: %.2fx\n",
           (double)(N * sizeof(uint16_t)) / (double)sizeof(packed));

    return 0;
}
