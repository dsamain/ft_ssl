#include "rsa.h"

#define SIEVE_LIMIT 10000

// return list of prime below SIEVE_LIMIT (0 terminated)
void init_sieve(u_int64_t *primes) {
    u_int8_t sieve[SIEVE_LIMIT];
    for (int i = 0; i < SIEVE_LIMIT; i++)
        sieve[i] = 1;
    for (u_int64_t i = 2; i * i < SIEVE_LIMIT; i++)
        for (u_int64_t j = i * i; j < SIEVE_LIMIT; j += i)
            sieve[j] = 0;
    u_int32_t cnt = 0;
    for (int i = 2; i < SIEVE_LIMIT; i++)
        cnt += sieve[i];
    primes[cnt--] = 0;
    for (int i = SIEVE_LIMIT - 1; i > 1; i--)
        if (sieve[i])
            primes[cnt--] = i;
}

u_int8_t sieve_test(u_int64_t n) {
    static u_int64_t primes[SIEVE_LIMIT] = {0};
    if (!primes[0])
        init_sieve(primes);
    for (int i = 0; primes[i] && n <= primes[i]; i++)
        if (n % primes[i] == 0)
            return 0;
    return 1;
}

// n = number to test, k = precision
//source: https://fr.wikipedia.org/wiki/Test_de_primalit%C3%A9_de_Miller-Rabin
u_int8_t is_prime(u_int64_t n, u_int32_t k, u_int32_t *rm_cnt) {
    // corner case cause rabin miller is not working even numbers (and numbers below 4 apparently)
    if (n <= 4)
        return (n == 2 || n == 3);
    // compute s, d such that (2^s)*d == n-1
    u_int64_t s = 0;
    u_int64_t d = n - 1;
    while (d % 2 == 0)
        s++, d >>= 1;
    
    for (u_int32_t j = 0; j < k; j++) {
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
        if (j == 0)
            *rm_cnt += 1;
    }
    return 1;
}

u_int64_t gen_prime(u_int32_t bits) {
    u_int32_t s_cnt = 0, rm_cnt = 0;
    while (1) {
        u_int64_t p = rand_range((u_int64_t)1 << (bits-1), ((u_int64_t)1 << bits) - 2);
        if (!sieve_test(p))
            continue;
        s_cnt++;
        if (is_prime(p, PRECISION, &rm_cnt)) {
            for (u_int32_t i = 0; i < s_cnt; i++)
                PUT(".");
            for (u_int32_t i = 0; i < rm_cnt; i++)
                PUT("+");
            PUT("\n");
            return p;
        }
        
    }
}