#include "../ft_ssl.h"

char *md5(char *s, size_t sz);

t_command g_hash[5] = {
    {"md5", md5, 16, "pqrs"}, 
    {"sha224", sha224, 28, "pqrs"}, 
    {"sha256", sha256, 32, "pqrs"}, 
    {"sha384", sha384, 48, "pqrs"}, 
    {"sha512", sha512, 64, "pqrs"},
};

t_command g_cipher[4] = {
    {"base64", base64, 0, "deio"}, 
    {"des", des, 0, "adeikopsv"}, 
    {"des-ecb", des, 0, "adeikopsv"}, 
    {"des-cbc", des, 0, "adeikopsv"},
};

void show_hash(t_command command, t_hash_args args, int flags) {

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

void hash(t_command *command, int ac, char **av) {
    int flags = 0;
    t_hash_args *args = parse_hash(ac, av, &flags);
    while (args) {
        args->output = (u_int8_t *)((char *(*)(char *, size_t))command->f)(args->content, ft_strlen(args->content));
        show_hash(*command, *args, flags);
        args = args->next;
    }
}

void cipher(t_command *command, int ac, char **av) {
    int flags = 0;
    t_cipher_args args = parse_cipher(ac, av, &flags, command);

    ((void(*)(t_cipher_args *, int))command->f)(&args, flags);
}


int main(int ac, char **av) {

    if (ac == 1) {
        help();
        return 0;
    }
    
    t_command *command;
    if ((command = find_command(av[1], g_hash, sizeof(g_hash)))) {
        hash(command, ac, av);
    } else if ((command = find_command(av[1], g_cipher, sizeof(g_cipher)))) {
        cipher(command, ac, av);
    } else {
        help();
        //throw(cat("ft_ssl: \"", av[1], "\" is an invalid command.\n"));
    }
}