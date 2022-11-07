#include "../ft_ssl.h"


u_int64_t parse_hex_to_u64(char *key) {
    u_int64_t ret = 0;
    size_t len = ft_strlen(key);
    char *base = "0123456789abcdef";
    for (size_t i = 0; i < 16; i++) {
        ret <<= 4;
        if (i < len) {
            char *p = ft_strchr(base, ft_tolower(key[i]));
            if (!p) throw("Invalid character\n");
            ret |= (p - base);
        }
    }
    //dprintf(2, "ft_key: %lx", ret);
    return ret;

}


t_cipher_args parse_cipher(int ac, char **av, int *flags, t_command *command) {
    t_cipher_args ret = INIT_CIPHER_ARGS;

    if (!ft_strncmp(av[1], "des", 3))
        ret.mode = (!ft_strcmp(av[1], "des") || !ft_strcmp(av[1], "des-cbc")) ? MODE_CBC : MODE_ECB;

    for (int i = 2; i < ac ; i++) {
        if (av[i][0] != '-') {
            throw("Extra arguments given.\n");
        }

        if (!ft_strchr(command->available_flags, av[i][1])) {
            throw("Invalid flag given.\n");
        }
        
        if (!ft_strcmp(av[i], "-e")) {

            *flags |= FLAG_E;

        } else if (!ft_strcmp(av[i], "-d")) {

            *flags |= FLAG_D;

        } else if (!ft_strcmp(av[i], "-k")) { // key in hex

            *flags |= FLAG_K;

            if (i + 1 >= ac) 
                throw("Missing key\n");

            ret.key = parse_hex_to_u64(av[++i]);

        } else if (!ft_strcmp(av[i], "-i")) { // input file

            *flags |= FLAG_I;
            if (i + 1 >= ac) throw("Missing input file\n");

            int fd = open(av[i + 1], O_RDONLY);

            if (fd < 0) 
                throw(cat("ft_ssl: ", av[1], ": ", av[i], ": No such file or directory\n"));

            ret.text = (char *)read_fd(fd, &ret.text_len);
            i++;

        } else if (!ft_strcmp(av[i], "-o")) {

            *flags |= FLAG_O;
            if (i + 1 >= ac) 
                throw("Missing output file\n");

            ret.out_fd = open(av[i + 1], O_WRONLY | O_CREAT | O_TRUNC, 0777);

            if (ret.out_fd < 0) 
                throw(cat("ft_ssl: ", av[1], ": ", av[i], ": No such file or directory\n"));
            i++;

        } else if (!ft_strcmp(av[i], "-v")) {

            *flags |= FLAG_V;

            if (i + 1 >= ac) 
                throw("Missing initialization vector\n");

            ret.iv = parse_hex_to_u64(av[++i]);

        } else if (!ft_strcmp(av[i], "-p")) {

            *flags |= FLAG_P;

            if (i + 1 >= ac) 
                throw("Missing password\n");

            ret.pass = av[++i];
        
        } else if (!ft_strcmp(av[i], "-s")) {

            *flags |= FLAG_S;
            if (i + 1 >= ac) 
                throw("Missing salt\n");

            ret.salt = parse_hex_to_u64(av[++i]);

        } else if (!ft_strcmp(av[i], "-a")) {

            *flags |= FLAG_A;

        } else {

            throw(cat("ft_ssl: ", av[1], ": ", av[i], ": Invalid option\n"));

        }
    }

    if (ret.mode == MODE_CBC && !(*flags & FLAG_V))
        throw("iv undefined\n");

    return ret;
}

t_hash_args *parse_hash(int ac, char **av, int *flags) {
    t_hash_args *ret = NULL;
    u_int8_t f = 0;
    int i;

    // read flags
    for (i = 2; i < ac && av[i][0] == '-'; i++) {
        if (!ft_strcmp(av[i], "-r")) {
            *flags |= FLAG_R;
        } else if (!ft_strcmp(av[i], "-q")) {
            *flags |= FLAG_Q;
        } else if (!ft_strcmp(av[i], "-s")) {
            if (i == ac - 1)
                throw(cat("ft_ssl: ", av[1], ": Expeted a string after -s.\nexample: ft_ssl command -s \"pouet\"\n"));
            push_hash_args(&ret);
            ret->source = cat((*flags & FLAG_R ? "" : str_to_upper(av[1])), "(\"", av[i + 1], "\")");    
            ret->content = cat(av[i + 1]);
            i++;
            f |= 1;
        } else if (!ft_strcmp(av[i], "-p")) {
            push_hash_args(&ret);
            ret->content = (char *)read_fd(0, NULL);
            ret->source = cat(ret->content);
            ret->source[ft_strlen(ret->source) - 1] = 0;
            ret->source = cat("(\"", ret->source, "\")");
            f |= 1;
        } else if (!ft_strcmp(av[i], "-h")) {
            help();
            exit(0);
        } 
    }

    // read files
    if (i == ac && !f) {
            push_hash_args(&ret);
            ret->content = (char *)read_fd(0, NULL);
            ret->source = cat("(stdin)");
    } else {
        for (; i < ac; i++) {
            int fd = open(av[i], O_RDONLY);
            if (fd < 0) {
                PUT_ERR(cat("ft_ssl: ", av[1], ": ", av[i], ": No such file or directory\n"));
                continue;
            } 
            push_hash_args(&ret);
            ret->content = (char *)read_fd(fd, NULL);
            ret->source = cat((*flags & FLAG_R ? "" : str_to_upper(av[1])), "(", av[i], ")");    
            close(fd);
        }
    }
    return ret;
}
