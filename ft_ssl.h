#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "src/str.h"


#define DEBUG

#ifdef DEBUG
    #include <stdio.h>
    #include <string.h>
    #define dbg(x) {dprintf(2, "[%s] %d: %s= %s\n", __FILE__, __LINE__, #x, x);}
#else
    #define dbg(x)
#endif

#define little_endian(x) ((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24)
#define left_rotate(x, y) ((x << y) | (x >> (32 - y))) 
#define right_rotate(x, n) ((x >> n) | (x << (32 - n)))
#define right_rotate_ll(x, n) ((x >> n) | (x << (64 - n)))

typedef struct s_commmand {
    char *name;
    char *(*f)(char *s);
    size_t output_size;    
} t_command;

typedef struct s_args {
    char            *source;
    char            *content;
    u_int8_t        *output;
    struct s_args   *next;
} t_args;

extern t_command g_commands[5];

static inline void put_hex(u_int8_t *a, int size) {
    char base[16] = "0123456789abcdef";
    for (int i = 0; i < size; i++) {
        write(1, &base[a[i] >> 4], 1);
        write(1, &base[a[i] & 0xf], 1);
    }
}

static inline void putb(unsigned int n) {
    if (n > 1) putb(n>>1);
    write(1, &"01"[n&1], 1);
}

static inline t_command *find_command(char *s) {
    for (int i = 0; i < sizeof(g_commands) / sizeof(t_command); i++) {
        if (!ft_strcmp(g_commands[i].name, s))
            return g_commands + i;
    }
    return NULL;
}

static inline void push_args(t_args **args) {
    t_args *new = malloc(sizeof(t_args)); 
    *new = (t_args){0, 0, 0, (*args ? *args : NULL)};
    *args = new;
}

static inline int help() {
    PUT("\nUsage:\n");
    PUT("  ft_ssl command [command opts] [command args]\n");
    PUT("\nOptions:\n");
    PUT("  -s  print the sum of the given string.\n");
    PUT("  -p  echo STDIN to STDOUT and append the checksum to STDOUT.\n");
    PUT("  -r  reverse the format of the output.\n");
    PUT("  -q  quiet mode.\n");

    return (0);
}

static inline void *ft_malloc(size_t size) {
    void *ret = malloc(size);
    if (!ret) throw("malloc error");
    return ret;
}

t_args *parse(int ac, char **av, int *flags);

u_int8_t *padding(char *s, size_t *len);
u_int8_t *padding_512(char *s, size_t *len);

char *md5(char *s);
char *sha224(char *s);
char *sha256(char *s);
char *sha384(char *s);
char *sha512(char *s);
