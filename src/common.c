#include "../ft_ssl.h"

void put_hex(u_int8_t *a, int size) {
    char base[16] = "0123456789abcdef";
    for (int i = 0; i < size; i++) {
        write(1, &base[a[i] >> 4], 1);
        write(1, &base[a[i] & 0xf], 1);
    }
}

void putb(u_int64_t n) {
    if (n > 1) putb(n>>1);
    write(1, &"01"[n&1], 1);
}

int help() {
    PUT("Usage:\n");
    PUT("  ft_ssl command [command opts] [command args]\n");
    PUT("\nMessage Digest commands:\n");
    PUT("  md5\n");
    PUT("  sha224\n");
    PUT("  sha256\n");
    PUT("  sha384\n");
    PUT("  sha512\n");
    PUT("\nCipher commands:\n");
    PUT("  base64\n");
    PUT("  des\n");
    PUT("\nOptions:\n");
    PUT("  -s  print the sum of the given string.\n");
    PUT("  -p  echo STDIN to STDOUT and append the checksum to STDOUT.\n");
    PUT("  -r  reverse the format of the output.\n");
    PUT("  -q  quiet mode.\n");

    return (0);
}

t_command *find_command(char *name, t_command *commands, size_t commands_size) {
    for (int i = 0; i < commands_size / sizeof(t_command); i++)
        if (!ft_strcmp(name, commands[i].name))
            return commands + i;

    return NULL;
}

void push_hash_args(t_hash_args **args) {
    t_hash_args *new = malloc(sizeof(t_hash_args)); 
    *new = (t_hash_args){0, 0, 0, (*args ? *args : NULL)};
    *args = new;
}

void *ft_malloc(size_t size) {
    void *ret = malloc(size);
    if (!ret) throw("malloc error");
    return ret;
}

u_int64_t str_to_u64(char *s) {
    char *base = "0123456789abcdef";
    u_int64_t ret = 0;
    for (int i = 0; s[i]; i++) {
        char *p = ft_strchr(base, s[i]);
        if (!p) throw("Invalid char in str_to_u64\n");
        ret = ret * 16 + (p - base);
    }
    return ret;
}