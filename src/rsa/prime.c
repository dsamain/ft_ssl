#include "rsa.h"

// n = number to test, k = precision
//source: https://fr.wikipedia.org/wiki/Test_de_primalit%C3%A9_de_Miller-Rabin
u_int8_t is_prime(u_int64_t n, u_int32_t k) {
    // corner case cause rabin miller is not working even numbers (and numbers below 4 apparently)
    if (n <= 4)
        return (n == 2 || n == 3);
    // compute s, d such that (2^s)*d == n-1
    u_int64_t s = 0;
    u_int64_t d = n - 1;
    while (d % 2 == 0)
        s++, d >>= 1;
    
    for (u_int32_t _ = 0; _ < k; _++) {
        u_int64_t a = rand_range(2, n - 2);
        u_int64_t x = powmod(a, d, n); 
        for (u_int64_t i = 0; i < s; i++) {
            u_int64_t y = (x * x) % n;
            if (y == 1 && x != 1 && x != n - 1)
                return 0;
            x = y;
        }
        if (x != 1)
            return 0;
    }
    return 1;
}

u_int64_t gen_prime(u_int32_t bits) {
    while (1) {
        u_int64_t p = rand_range((u_int64_t)1 << (bits-1), ((u_int64_t)1 << bits) - 1);
        if (is_prime(p, PRECISION))
            return p;
    }
}