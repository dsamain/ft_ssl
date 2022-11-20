#include "rsa.h"

void parse_gen_rsa(int ac, char **av) {
    (void)ac, (void)av;
}

void gen_rsa(int ac, char **av) {
    PUT("Generating RSA private key, 64 bit long modulus (2 primes)\n");

    t_rsa_key key = INIT_RSA_KEY;

    key.p = gen_prime(KEY_SIZE / 2);
    key.q = gen_prime(KEY_SIZE / 2);
    key.n = key.p * key.q;
    key.phi = (key.p - 1) * (key.q - 1);
    key.d = invmod(key.e, key.phi);
    key.d1 = key.d % (key.p - 1);
    key.d2 = key.d % (key.q - 1);
    key.qinv = invmod(key.q, key.p);

    //dbg("p q n = %lu %lu %lu\n", key.p, key.q, key.n);

    char *b64_key = rsa_key_pem(&key);
    PUT("-----BEGIN RSA PRIVATE KEY-----\n");
    PUT(b64_key);
    PUT("\n-----END RSA PRIVATE KEY-----\n");

    (void)ac, (void)av;
}