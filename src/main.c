#include "../ft_ssl.h"

t_command g_commands[2] = {
    {"md5", md5}, 
    {"sha256", sha256},
};

void show(t_args args, int flags) {
    PUT(args.source);
    PUT("= ");
    put_hex(args.output, 16);
    PUT("\n");
}



int main(int ac, char **av) {
    if (ac == 1) {
        return help();
    }
    
    // function pointer
    char *(*f)(char *s) = find_command(av[1]);
    if (!f) {
        throw(ft_join(ft_join("ft_ssl: \"", av[1]), "\" is an invalid command.\n"));
    }
    int flags = 0;
    t_args *args = parse(ac, av, &flags);
    while (args) {
        args->output = f(args->content);
        show(*args, flags);
        args = args->next;
    }
}