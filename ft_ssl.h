#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#define DEBUG

#ifdef DEBUG
    #include <stdio.h>
    #include <string.h>
    #define dbg(x) {dprintf(2, "[%s] %d: %s= %s\n", __FILE__, __LINE__, #x, x);}
#else
    #define dbg(x)
#endif

#define PUT(x) write(1, x, ft_strlen(x))
#define PUT_ERR(x) write(2, x, ft_strlen(x))
#define throw(x) {PUT_ERR(x); exit(1);}
#define cat(...) (cat_f(__VA_ARGS__, NULL))

#define BUFF_SIZE 1024

#define FLAG_Q (1 << 0)
#define FLAG_R (1 << 1)
#define FLAG_A (1 << 2)
#define FLAG_D (1 << 2)
#define FLAG_E (1 << 2)
#define FLAG_I (1 << 2)
#define FLAG_K (1 << 2)
#define FLAG_O (1 << 2)
#define FLAG_P (1 << 2)
#define FLAG_S (1 << 2)
#define FLAG_V (1 << 2)

#define little_endian(x) ((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24)
#define left_rotate(x, y) ((x << y) | (x >> (32 - y))) 
#define right_rotate(x, n) ((x >> n) | (x << (32 - n)))
#define right_rotate_ll(x, n) ((x >> n) | (x << (64 - n)))

typedef struct s_commmand {
    char *name;
    char *(*f)(char *s);
    size_t output_size;    
    char *available_flags;
} t_command;

typedef struct s_hash_args {
    char            *source;
    char            *content;
    u_int8_t        *output;
    struct s_hash_args   *next;
} t_hash_args;

extern t_command g_hash[5];
extern t_command g_encode[4];

// common
t_command *find_command(char *s, t_command *commands, size_t command_size);
void put_hex(u_int8_t *a, int size);
void putb(unsigned int n);
void push_hash_args(t_hash_args **args);
void *ft_malloc(size_t size);
int help();

// parsing
t_hash_args *parse_hash(int ac, char **av, int *flags);

// hash
char *md5(char *s);
char *sha224(char *s);
char *sha256(char *s);
char *sha384(char *s);
char *sha512(char *s);

// padding
u_int8_t *padding(char *s, size_t *len);
u_int8_t *padding_512(char *s, size_t *len);

// str
char *to_upper(char *s);
int ft_strcmp(char *s, char *t);
char *cat_f(char *s, ...);
char *ft_join(char *s, char *t);
int ft_strlen(char *s);