#include "../ft_ssl.h"

t_command g_hash[5] = {
    {"md5", md5, 16}, 
    {"sha224", sha224, 28, "pqrs"}, 
    {"sha256", sha256, 32, "pqrs"}, 
    {"sha384", sha384, 48, "pqrs"}, 
    {"sha512", sha512, 64, "pqrs"},
};

t_command g_cipher[4] = {
    {"base64", NULL, 0, "deio"}, 
    {"des", NULL, 0, "adeikopsv"}, 
    {"des-ecb", NULL, 0, "adeikopsv"}, 
    {"des-cbc", NULL, 0, "adeikopsv"},
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
        args->output = command->f(args->content);
        show_hash(*command, *args, flags);
        args = args->next;
    }
}

void cipher(t_command *command, int ac, char **av) {
    int flags = 0;
    t_cipher_args args = parse_cipher(ac, av, &flags);

    des_ecb(&args, flags);
}


int main(int ac, char **av) {

    //printf("num: \n");
    //putb(str_to_u64("8888"));
    //PUT("\n");
    

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
        throw(cat("ft_ssl: \"", av[1], "\" is an invalid command.\n"));
    }
}