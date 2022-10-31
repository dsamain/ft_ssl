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
