#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define DEBUG

#ifdef DEBUG
    #include <stdio.h>
    #include <string.h>
    #define dbg(s, ...) {dprintf(2, "dbg: "); dprintf(2, "%s", __VA_ARGS__);}
#else
    #define dbg(x)
#endif

// io 
#define PUT(x) write(1, x, ft_strlen(x))
#define PUT_ERR(x) write(2, x, ft_strlen(x))
#define throw(x) {PUT_ERR("Error: "); PUT_ERR(x); exit(1);}
#define cat(...) (cat_f(__VA_ARGS__, NULL))

// Hash 
#define little_endian(x) ((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24)
#define left_rotate(x, y) ((x << y) | (x >> (32 - y))) 
#define right_rotate(x, n) ((x >> n) | (x << (32 - n)))
#define right_rotate_ll(x, n) ((x >> n) | (x << (64 - n)))

// bit manipulation
#define at(x, i, size) ((x >> (size - (i) - 1)) & 1)
#define assign(x, shift, val) (x = (x & ~((u_int64_t)1 << shift)) ^ ((u_int64_t)val << shift))
#define c_left_shift(x, shift, size) (((x << shift) | (x >> (size - shift))) & ((1 << size) - 1))

#define BUFF_SIZE 1024

// flags
#define FLAG_Q (1 << 0)
#define FLAG_R (1 << 1)
#define FLAG_A (1 << 2)
#define FLAG_D (1 << 3)
#define FLAG_E (1 << 4)
#define FLAG_I (1 << 5)
#define FLAG_K (1 << 6)
#define FLAG_O (1 << 7)
#define FLAG_P (1 << 8)
#define FLAG_S (1 << 9)
#define FLAG_V (1 << 10)

// des modes
#define MODE_ECB (1 << 0)
#define MODE_CBC (1 << 1)


typedef struct s_commmand {
    char *name;
    //char *(*f)(char *s);
    void *f;
    size_t output_size;    
    char *available_flags;
} t_command;

typedef struct s_hash_args {
    char            *source;
    char            *content;
    u_int8_t        *output;
    struct s_hash_args   *next;
} t_hash_args;

#define INIT_CIPHER_ARGS {(size_t)0, (char *)0, (u_int64_t)0, (u_int64_t)0, (char *)0, (size_t)0, (char *)0, (int)1, MODE_ECB}

typedef struct t_cipher_args {
    u_int64_t iv; // initial permutation
    char *pass;
    u_int64_t salt;
    u_int64_t key;
    char *text;
    size_t text_len;
    char *output;
    int out_fd;
    u_int8_t mode;
} t_cipher_args;

extern t_command g_hash[5];
extern t_command g_cipher[4];

// common
t_command *find_command(char *s, t_command *commands, size_t command_size);
void put_hex(u_int8_t *a, int size);
void put_hex_n(u_int64_t a, int size);
void push_hash_args(t_hash_args **args);
void *ft_malloc(size_t size);
u_int64_t str_to_u64(char *s);
u_int8_t *read_fd(int fd, size_t *len);
void show_hash(t_command command, t_hash_args args, int flags);
int help();

// dbg
void putb(u_int64_t n);
void putb_u64(u_int64_t n);
void putb_n(u_int64_t n, int size);

// parsing
t_hash_args *parse_hash(int ac, char **av, int *flags);
t_cipher_args parse_cipher(int ac, char **av, int *flags, t_command *command);


// hash
char *md5(char *s, size_t sz);
char *sha224(char *s, size_t sz);
char *sha256(char *s, size_t sz);
char *sha384(char *s, size_t sz);
char *sha512(char *s, size_t sz);
char *pbkdf2(char *password, char *salt, int iterations, int key_len);
char *hmac_sha256(u_int8_t *text, size_t text_len, u_int8_t *key, size_t key_len);

// cipher
void des(t_cipher_args *args, int flags);
void base64(t_cipher_args *args, int flags);
char *encrypt_base64(char *text, size_t text_len, size_t *ret_len);
char *decrypt_base64(char *text, size_t text_len, size_t *ret_len);

// padding
u_int8_t *padding(char *s, size_t sz, size_t *len);
u_int8_t *padding_512(char *s, u_int64_t sz, size_t *len);

// str
char *str_to_upper(char *s);
int ft_strcmp(char *s, char *t);
int ft_strncmp(char *s, char *t, int n);
char *ft_join(char *s, char *t);
char *ft_join_len(char *s, size_t s_len, char *t, size_t t_len);
int ft_strlen(char *s);
char *ft_strchr(char *s, char c);
char *cat_f(char *s, ...);
char ft_tolower(char c);