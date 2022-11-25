#pragma once

#include "../../ft_ssl.h"

#define KEY_SIZE 64 // number of bits in the key
#define PRECISION 1000 // number of iterations for rabin millerk
#define PUBLIC_EXPONENT 65537

typedef u_int64_t ull;
#define ASN1_NUMBER 0x02
#define ASN1_SEQUENCE 0x30
#define ASN1_OI 0x06
#define ASN1_BIT_STRING 0x03
#define ASN1_NULL 0x05

// public key (n) = p * q
// phi = (p - 1) * (q - 1)
// private key (d) = e^-1 mod phi
// public exponent (e) = 65537

// encryption : m^e mod n
// decryption : (m^e mod n)^d mod n

// rsa based on : 
// (message ^ public exponent mod public key) ^ private exponent mod public key = message

#define INIT_RSA_ARGS {1, 0, (char *)NULL, (size_t)0}
typedef struct s_rsa_args {
    int out_fd;
    int in_fd;
    char *content;
    size_t content_len;
} t_rsa_args;

//ft_ssl rsautl [-in file] [-out file] [-inkey file] [-pubin] [-encrypt] [-decrypt] [-hexdump]
#define INIT_RSAUTL_ARGS {1, 0, -1, (char *)NULL, (char *)NULL, (size_t)0, (size_t)0}
typedef struct s_rsautl_args {
    int out_fd;
    int in_fd;
    int in_key_fd;
    char *content;
    char *key;
    size_t content_len;
    size_t key_len;
} t_rsautl_args;

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

#define INIT_RSA_PRIVATE_ASN1 {0, 0, 0, 0, 0, 0, 0, 0, 0, (size_t)0, (size_t)0, (size_t)0, (size_t)0, (size_t)0,  (size_t)0, (size_t)0, (size_t)0, (size_t)0}
typedef struct s_rsa_private_asn1 {
    u_int8_t *version;
    u_int8_t *modulus;
    u_int8_t *publicExponent;
    u_int8_t *privateExponent;
    u_int8_t *prime1;
    u_int8_t *prime2;
    u_int8_t *exponent1;
    u_int8_t *exponent2;
    u_int8_t *coefficient;
    size_t version_len;
    size_t modulus_len;
    size_t publicExponent_len;
    size_t privateExponent_len;
    size_t prime1_len;
    size_t prime2_len;
    size_t exponent1_len;
    size_t exponent2_len;
    size_t coefficient_len;
} t_rsa_private_asn1;

#define INIT_RSA_PUBLIC_ASN1 {0, 0, 0, (size_t)0, (size_t)0, (size_t)0}
typedef struct s_rsa_public_asn1 {
    u_int8_t *algorithm;
    u_int8_t *publicKey;
    u_int8_t *publicExponent;
    size_t algorithm_len;
    size_t publicKey_len;
    size_t publicExponent_len;
} t_rsa_public_asn1;

//ft_ssl rsa [-inform PEM] [-outform PEM] [-in file] [-passin arg] [-out file] [-passout arg] [-des] [-
//text] [-noout] [-modulus] [-check] [-pubin] [-pubout]

// RSA FLAGS
#define RSA_FLAG_INFORM 1 << 0 
#define RSA_FLAG_OUTFORM 1 << 1 
#define RSA_FLAG_IN 1 << 2 
#define RSA_FLAG_PASSIN 1 << 3 
#define RSA_FLAG_OUT 1 << 4 
#define RSA_FLAG_PASSOUT 1 << 5
#define RSA_FLAG_DES 1 << 6
#define RSA_FLAG_TEXT 1 << 7
#define RSA_FLAG_NOOUT 1 << 8
#define RSA_FLAG_MODULUS 1 << 9
#define RSA_FLAG_CHECK 1 << 10
#define RSA_FLAG_PUBIN 1 << 11
#define RSA_FLAG_PUBOUT 1 << 12



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
char *rsa_key_pem_64(t_rsa_key *key);
t_rsa_private_asn1 parse_private_key(t_rsa_args *args);
t_rsa_public_asn1 parse_public_key(t_rsa_args *args);
void asn1_private_to_public(t_rsa_private_asn1 *private_key);

void test_asn1_build();