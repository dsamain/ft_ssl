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


t_args *parse(int ac, char **av, int *flags) {
    t_args *ret = NULL;
    int i;

    // read flags
    for (i = 2; i < ac && av[i][0] == '-'; i++) {
        if (!ft_strcmp(av[i], "-r")) {
            *flags |= FLAG_R;
        } else if (!ft_strcmp(av[i], "-q")) {
            *flags |= FLAG_R;
        } else if (!ft_strcmp(av[i], "-s")) {
            if (i == ac - 1)
                throw(ft_join("ft_ssl: ", ft_join(av[1], ": Expeted a string after -s.\nexample: ft_ssl command -s \"pouet\"\n")));
            push_args(&ret);
            ret->source = ft_join(to_upper(av[1]), ft_join(" (\"", ft_join(av[i + 1], "\")")));    
            ret->content = ft_join(av[i + 1], NULL);
            i++;
        } else if (!ft_strcmp(av[i], "-p")) {
            push_args(&ret);
            ret->content = read_fd(0);
            ret->source = ft_join("(\"", ft_join(ret->content, "\")"));
        }
    }

    // read files
    if (i == ac) {
            push_args(&ret);
            ret->content = read_fd(0);
            ret->source = ft_join("(stdin)", NULL);
    } else {
        for (; i < ac; i++) {
            int fd = open(av[i], O_RDONLY);
            if (fd < 0) {
                PUT_ERR(ft_join("ft_ssl: ", ft_join(av[1], ft_join(": ", ft_join(av[i], ": No such file or directory\n")))));
                continue;
            } 
            push_args(&ret);
            ret->content = read_fd(fd);
            ret->source = ft_join(to_upper(av[1]), ft_join("(", ft_join(av[i], ")")));    
            close(fd);
        }
    }
    return ret;
}
