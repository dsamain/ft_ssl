#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "src/str.h"

#define DEBUG

#ifdef DEBUG
    #include <stdio.h>
    #define dbg(x) {dprintf(2, "[%s] %d: %s= %s\n", __FILE__, __LINE__, #x, x);}
#else
    #define dbg(x)
#endif

#define BUFF_SIZE 1024


#define FLAG_Q 1
#define FLAG_R 2

typedef struct s_commmand {
    char *name;
    char *(*f)(char *s);
} t_command;

typedef struct s_args {
    char *source;
    char *content;
    char *output;
    struct s_args *next;
} t_args;

extern t_command g_commands[2];

static inline void push_args(t_args **args) {
    t_args *new = malloc(sizeof(t_args)); 
    if (!new) {
        throw("malloc error");
    }
    *new = (t_args){0, 0, 0, (*args ? *args : NULL)};
    *args = new;
}

static inline void putb(unsigned int n) {
    if (n) putb(n>>1);
    write(1, &"01"[n&1], 1);
}

static inline void *find_command(char *s) {
    for (int i = 0; i < sizeof(g_commands) / sizeof(t_command); i++) {
        if (!ft_strcmp(g_commands[i].name, s))
            return g_commands[i].f;
    }
    return NULL;
}

static inline int help() {
    PUT("usage: ft_ssl command [command opts] [command args]\n");
    return (1);
};

char *md5(char *s);
char *sha256(char *s);