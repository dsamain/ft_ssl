#pragma once

#include "../../ft_ssl.h"

#define KEY_SIZE 64 // number of bits in the key
#define PRECISION 1000 // number of iterations for rabin millerk
#define PUBLIC_EXPONENT 65537

typedef u_int64_t ull;
#define ASN1_NUMBER 0x02
#define ASN1_SEQUENCE 0x30

#define INIT_RSA_KEY {(ull)0, (ull)0, (ull)PUBLIC_EXPONENT, (ull)0, (ull)0, (ull)0, (ull)0, (ull)0, (ull)0}
typedef struct s_rsa_key {
    u_int64_t p; // prime 1
    u_int64_t q; // prime 2
    u_int64_t e; // public exponent
    u_int64_t d; // private exponent
    u_int64_t n; // modulus
    u_int64_t phi; // totient
    u_int64_t d1; // d mod (p - 1)
    u_int64_t d2; // d mod (q - 1)
    u_int64_t qinv; // q^-1 mod p
} t_rsa_key;


// n  = p * q
// phi = (p - 1) * (q - 1)
// d = e^-1 mod phi

// encryption : m^e mod n
// decryption : (m^e mod n)^d mod n


static inline u_int64_t addmod(u_int64_t a, u_int64_t b, u_int64_t n) {
    a %= n, b %= n;
    if (n - a <= b) {
        u_int64_t tmp = n - a;
        return b - tmp;
    } 
    return (a + b) % n;
}

// compute (x*y) % mod ( O(log(y) )
static inline u_int64_t mulmod(u_int64_t x, u_int64_t y, u_int64_t mod) {
    u_int64_t res = 0;
    x %= mod;
    y %= mod;
    while (y) {
        if (y & 1) {
            //res = (res + x) % mod;
            res = addmod(res, x, mod);
        }
        //x = (x + x) % mod;
        x = addmod(x, x, mod);
        y >>= 1;
    }
    return res;
}

// compute (x^y) % mod ( O(log(y) )
static inline __int128_t powmod(__int128_t x, __int128_t y, __int128_t mod) {
    __int128_t res = 1;
    while (y) {
        if (y & 1)
            res = mulmod(res, x, mod) % mod;
        x = mulmod(x, x, mod) % mod;
        y >>= 1;
    }
    return res;
}

//compute inverse of n mod m ( O(log(m) )
//https://rosettacode.org/wiki/Modular_inverse#C
static inline __int128_t invmod(__int128_t a, __int128_t b) {
    a %= b;
    __int128_t b0 = b, t, q;
    __int128_t x0 = 0, x1 = 1;
    if (b == 1) return 1;
    while (a > 1) {
        q = a / b;
        t = b, b = a % b, a = t;
        t = x0, 
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += b0;
    return x1;
}


// generate random number in range [l, r)
// we can't use rand() so we read in urandom instead
static inline u_int64_t rand_range(u_int64_t l, u_int64_t r) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (!fd) 
        throw("Error opening /dev/urandom");
    u_int64_t ret;
    if (read(fd, &ret, sizeof(ret)) < 0)
        throw("Error reading /dev/urandom");
    close(fd);
    return (ret % (r - l) + l);
}


u_int8_t is_prime(u_int64_t n, u_int32_t k, u_int32_t *rm_cnt);
u_int64_t gen_prime();

// asn1
char *rsa_key_pem(t_rsa_key *key);