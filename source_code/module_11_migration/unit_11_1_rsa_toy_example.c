#include <stdint.h>
#include <stdio.h>

// Modular exponentiation: base^exp mod mod
// Using square-and-multiply algorithm
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base = base % mod;

    while (exp > 0) {
        // If exp is odd, multiply result with base
        if (exp & 1) {
            result = (__uint128_t)result * base % mod;
        }
        // exp must be even now
        exp = exp >> 1;
        base = (__uint128_t)base * base % mod;
    }
    return result;
}

// Extended Euclidean Algorithm for modular inverse
int64_t mod_inverse(int64_t a, int64_t m) {
    int64_t m0 = m, y = 0, x = 1;

    if (m == 1) return 0;

    while (a > 1) {
        int64_t q = a / m;
        int64_t t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }

    if (x < 0) x += m0;
    return x;
}

int main(void) {
    // Toy example with small primes (INSECURE - for education only)
    uint64_t p = 61, q = 53;
    uint64_t n = p * q;           // 3233
    uint64_t phi = (p-1) * (q-1); // 3120
    uint64_t e = 17;              // Public exponent
    uint64_t d = mod_inverse(e, phi); // Private exponent = 2753

    printf("RSA Toy Example:\n");
    printf("p = %lu, q = %lu\n", p, q);
    printf("n = %lu\n", n);
    printf("e = %lu (public)\n", e);
    printf("d = %lu (private)\n", d);

    // Encrypt and decrypt
    uint64_t message = 123;
    uint64_t ciphertext = mod_exp(message, e, n);
    uint64_t decrypted = mod_exp(ciphertext, d, n);

    printf("\nOriginal:  %lu\n", message);
    printf("Encrypted: %lu\n", ciphertext);
    printf("Decrypted: %lu\n", decrypted);

    return 0;
}
