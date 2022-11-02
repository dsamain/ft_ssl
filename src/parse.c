#include "../ft_ssl.h"

char *read_fd(int fd) {
    char *ret = NULL;
    char buf[BUFF_SIZE];

    int status;
    while ((status = read(fd, buf, BUFF_SIZE + 1))) {
        if (status == -1)
            throw("Error while reading");
        buf[status] = 0;
        ret = ft_join(ret, buf);
    }
    return ret;
}

//typedef struct t_cipher_args {
    //u_int64_t iv; // initial permutation
    //u_int64_t key;
    //char *text;
    //char *output;
//} t_cipher_args;


u_int64_t parse_key(char *key) {
    u_int64_t ret = 0;
    size_t len = ft_strlen(key);
    char *base = "0123456789ABCDEF";
    for (int i = 0; i < 16; i++) {
        ret <<= 4;
        if (i < len) {
            char *p = ft_strchr(base, ft_tolower(key[i]));
            ret |= (p - base) & 1;
        }
    }
    return ret;
}


t_cipher_args parse_cipher(int ac, char **av, int *flags) {
    t_cipher_args ret = INIT_CIPHER_ARGS;

    for (int i = 2; i < ac && av[i][0] == '-'; i++) {
        if (!ft_strcmp(av[i], "-e")) {
            *flags |= FLAG_E;
        } else if (!ft_strcmp(av[i], "-d")) {
            *flags |= FLAG_D;
        } else if (!ft_strcmp(av[i], "-k")) { // key in hex
            if (i + 1 >= ac) throw("Missing key\n");
            ret.key = parse_key(av[++i]);
        } else if (!ft_strcmp(av[i], "-i")) { // input file
            *flags |= FLAG_I;
            if (i + 1 >= ac) throw("Missing input file\n");
            int fd = open(av[i + 1], O_RDONLY);
            if (fd < 0) throw(cat("ft_ssl: ", av[1], ": ", av[i], ": No such file or directory\n"));
            ret.text = read_fd(fd);
            i++;
        } else if (!ft_strcmp(av[i], "-o")) {
            if (i + 1 >= ac) throw("Missing output file\n");
            ret.out_fd = open(av[i + 1], O_WRONLY | O_CREAT | O_TRUNC, 0);
            if (ret.out_fd < 0) throw(cat("ft_ssl: ", av[1], ": ", av[i], ": No such file or directory\n"));
            i++;
        } else {
            throw(cat("ft_ssl: ", av[1], ": ", av[i], ": Invalid option\n"));
        }
    }

    printf("ret fd : %d\n", ret.out_fd);
    if (!flags & FLAG_I) {
        PUT("Enter text to encrypt : \n");
        ret.text = read_fd(0);
    }

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
            ret->source = cat((*flags & FLAG_R ? "" : to_upper(av[1])), "(\"", av[i + 1], "\")");    
            ret->content = cat(av[i + 1]);
            i++;
            f |= 1;
        } else if (!ft_strcmp(av[i], "-p")) {
            push_hash_args(&ret);
            ret->content = read_fd(0);
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
            ret->content = read_fd(0);
            ret->source = cat("(stdin)");
    } else {
        for (; i < ac; i++) {
            int fd = open(av[i], O_RDONLY);
            if (fd < 0) {
                PUT_ERR(cat("ft_ssl: ", av[1], ": ", av[i], ": No such file or directory\n"));
                continue;
            } 
            push_hash_args(&ret);
            ret->content = read_fd(fd);
            ret->source = cat((*flags & FLAG_R ? "" : to_upper(av[1])), "(", av[i], ")");    
            close(fd);
        }
    }
    return ret;
}
