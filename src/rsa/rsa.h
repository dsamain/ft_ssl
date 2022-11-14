#include "../../ft_ssl.h"


// compute (x^n) % mod ( O(log(y) )
static inline u_int64_t powmod(u_int64_t x, u_int64_t y, u_int64_t mod) {
    u_int64_t res = 1;
    while (y) {
        if (y & 1)
            res = (res * x) % mod;
        x = (x * x) % mod;
        y >>= 1;
    }
    return res;
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


void gen_rsa(int ac, char **av);
u_int8_t is_prime(u_int64_t n, u_int32_t k);