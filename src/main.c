#include "../ft_ssl.h"

t_command g_commands[5] = {
    {"md5", md5, 16}, 
    {"sha224", sha224, 28},
    {"sha256", sha256, 32},
    {"sha384", sha384, 48},
    {"sha512", sha512, 64},
};

void show(t_command command, t_args args, int flags) {

    if (flags & FLAG_Q) {
        put_hex(args.output, command.output_size);
    } else if (flags & FLAG_R) {
        put_hex(args.output, command.output_size);
        args.source[ft_strlen(args.source) - 1] = 0;
        PUT(" ");
        PUT(args.source + 1);
    } else {
        PUT(args.source);
        PUT("= ");
        put_hex(args.output, command.output_size);
    }
    PUT("\n");
}


int main(int ac, char **av) {
    
    if (ac == 1) {
        help();
        return 0;
    }
    
    t_command *command = find_command(av[1]);
    if (!command) {
        throw(cat("ft_ssl: \"", av[1], "\" is an invalid command.\n"));
    }
    int flags = 0;
    t_args *args = parse(ac, av, &flags);
    while (args) {
        args->output = command->f(args->content);
        show(*command, *args, flags);
        args = args->next;
    }
}