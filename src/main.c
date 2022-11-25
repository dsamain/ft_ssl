//#include "../ft_ssl.h"
#include "rsa/rsa.h"

// t_command include command name, command function, output length, available options
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

t_command g_other[3] = {
    {"genrsa", genrsa, 0, ""},
    {"rsa", rsa, 0, ""},
    {"rsautl", rsautl, 0, ""},
};

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
    t_cipher_args args = parse_cipher(ac, av, &flags);

    ((void(*)(t_cipher_args *, int))command->f)(&args, flags);
}


int main(int ac, char **av) {

    test_asn1_build();
    return 0;
    //dbg("bonjour a tous\n");
    ////dbg("pouet = %d\n", 42);

    //char **tmp = ft_malloc(sizeof(char *) * 3);
    //tmp[0] = ft_malloc(sizeof(char) * 3, 1);
    //tmp[1] = ft_malloc(sizeof(char) * 3, 2);
    //tmp[2] = ft_malloc(sizeof(char) * 3, 42);

    //ft_free(0);
    //ft_free(1);
    //ft_free(2);
    //ft_free(42);
    //tmp[1] = ft_malloc(sizeof(char) * 3, 2);
    //tmp[1] = ft_malloc(sizeof(char) * 3, 2);
    //ft_free(1);
    //tmp[1] = ft_malloc(sizeof(char) * 3, 2);
    //dbg("tmp[1] : %s\n", tmp[1]);
    //throw("wouah\n");

    //return 0;
    if (ac == 1) {
        help();
        return 0;
    }
    
    t_command *command;
    if ((command = find_command(av[1], g_hash, sizeof(g_hash)))) {
        hash(command, ac, av);
    } else if ((command = find_command(av[1], g_cipher, sizeof(g_cipher)))) {
        cipher(command, ac, av);
    } else if ((command = find_command(av[1], g_other, sizeof(g_other)))) {
        ((void (*)(int, char **))command->f)(ac, av);
    } else {
        help();
    }
}