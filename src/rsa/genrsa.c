#include "rsa.h"

void genrsa_help() {
    PUT("Usage: genrsa [OPTION]\n");
    PUT("Valid options are:\n");
    PUT("  -h, --help\t\t\tDisplay this help and exit\n");
    PUT("  -o, --out <file>\t\tOutput file (default: stdout)\n");
}


void parse_genrsa(int ac, char **av, int *fd) {
    for (int i = 2; i < ac; i++) {
        if (!ft_strcmp(av[i], "-h") || !ft_strcmp(av[i], "--help")) {
            genrsa_help();
            exit(0);
        } else if (!ft_strcmp(av[i], "-o") || !ft_strcmp(av[i], "--out")) {
            if (i == ac - 1)
                throw(cat("ft_ssl: genrsa: option ", av[i], " requires an argument\n"));
            i++;
            *fd = open(av[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (*fd == -1)
                throw(cat("ft_ssl: genrsa: ", av[i], ": open error\n"));
        } else {
            throw(cat("ft_ssl: genrsa: invalid option -- ", av[i], "\n"));
        }
    }

}

void genrsa(int ac, char **av) {
    int out_fd = 1;
    parse_genrsa(ac, av, &out_fd);

    PUT("Generating RSA private key, 64 bit long modulus (2 primes)\n");

    t_rsa_key key = INIT_RSA_KEY;

    key.p = gen_prime(KEY_SIZE / 2);
    key.q = gen_prime(KEY_SIZE / 2);

    PUT("e is 65537 (0x10001)\n");

    key.n = key.p * key.q;
    key.phi = (key.p - 1) * (key.q - 1);
    key.d = invmod(key.e, key.phi);
    key.d1 = key.d % (key.p - 1);
    key.d2 = key.d % (key.q - 1);
    key.qinv = invmod(key.q, key.p);

    //dbg("p q n = %lu %lu %lu\n", key.p, key.q, key.n);

    char *b64_key = rsa_key_pem(&key);
    put_fd("-----BEGIN RSA PRIVATE KEY-----\n", out_fd);
    put_fd(b64_key, out_fd);
    put_fd("\n-----END RSA PRIVATE KEY-----\n", out_fd);

    if (out_fd != 1)
        close(out_fd);
}