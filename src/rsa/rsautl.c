#include "rsa.h"

t_rsautl_args parse_rsautl(int ac, char **av, int *flags) {
    (void)ac, (void)av, (void)flags;
    return (t_rsautl_args){0};
}

void rsautl(int ac, char **av)  {
    int flags = 0;
    t_rsautl_args args = INIT_RSAUTL_ARGS;
    args = parse_rsautl(ac, av, &flags);
    (void)ac, (void)av, (void)args;
    put_fd("called\n", 2);
}