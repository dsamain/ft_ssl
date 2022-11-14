#include "rsa.h"

void parse_gen_rsa(int ac, char **av) {
    (void)ac, (void)av;
}

u_int8_t is_prime2(u_int64_t n) {
    for (u_int64_t i = 2; i * i <= n; i++) {
        if (n % i == 0)
            return 0;
    }
    return 1;
}

void gen_rsa(int ac, char **av) {
    for (int i = 2; i < 10000; i++) {
        if (is_prime2(i) != is_prime(i, 100000)) {
            PUT("cringe\n");
            dbg("%d %d %d\n", i, is_prime2(i), is_prime(i, 100));
            //return;
        }
        if (is_prime(i, 100))
            dbg("i : %d\n", i);
        //if (is_prime(i, 100)) {
            //dbg("%d\n", i);
        //}
    }

    (void)ac, (void)av;
}