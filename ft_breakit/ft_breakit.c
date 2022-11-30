#include "../src/rsa/rsa.h"
#include <math.h>

#define PUBIN 1

u_int64_t ft_sqrt(u_int64_t n) {
    u_int64_t l = 1, r = n, res = n;
    while (r >= l) {
        __uint128_t mid = (__uint128_t)(l + r) / 2;
        if (mid * mid > n) {
            r = mid - 1;
        } else {
            l = mid + 1;
            res = mid;
        }
    }
    return res;
}

u_int64_t parse(int ac, char **av) {
    int flags = 0, fd = -1;
    for (int i = 1; i < ac; i++) {
        if (av[i][0] == '-') {
            if (!ft_strncmp(av[i], "-pubin", 6)) {
                flags |= PUBIN;
            } else {
                throw(cat("ft_breakit: invalid option -- '", av[i], "'\n"));
            }
        } else {
            fd = open(av[i], O_RDONLY);
            if (fd < 0)
                throw(cat("ft_breakit: ", av[i], ": No such file or directory\n"));
        }
    }
    if (fd < 0)
        throw("ft_breakit: no file specified\n");

    size_t len = 0; 
    char *key = read_fd(fd, &len);
    t_rsa_args rsa_args = INIT_RSA_ARGS;
    rsa_args.content = key;

    char *mod_str;
    size_t mod_len;

    if (flags & PUBIN) {
        t_rsa_public_asn1 pub = parse_public_key(&rsa_args);
        mod_str = pub.publicKey;
        mod_len = pub.publicKey_len;
    } else {
        t_rsa_private_asn1 priv = parse_private_key(&rsa_args);
        mod_str = priv.modulus;
        mod_len = priv.modulus_len;
    }
    while (mod_len > 0 && *mod_str == 0)
        mod_str++, mod_len--;

    if (mod_len > 8)
        throw("ft_breakit: key too long (64bit max)\n");
    
    u_int64_t mod = 0;
    for (int i = 0;i < mod_len; i++)
        mod = (mod << 8) | (u_int8_t)mod_str[i];
    return mod;
}

u_int8_t is_prime2(u_int64_t n) {

    for (__uint128_t i = 2; i * i <= n; i++) {
        if (n % i == 0)
            return 0;
    }
    return 1;
}

int main(int ac, char **av) {
    u_int64_t mod = parse(ac, av);
    u_int32_t i = ft_sqrt(mod);
    i -= (i % 2 == 0);
    for (; i > 0; i -= 2) {
        if (mod % i == 0 && is_prime2(i)) {
            printf("found factor :) %u %lu\n", i, mod / i);
            return 0;
        }
    }
}