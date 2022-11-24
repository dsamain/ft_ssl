#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "../../io.h"

#define throw(x) {free_all(); PUT_ERR("Error: "); PUT_ERR(x); exit(1);}
#define ft_malloc(x, ...) sizeof((int[]){__VA_ARGS__}) / sizeof(int) > 1 ? ft_malloc_(x, GC_DEFAULT) : ft_malloc_(x, sizeof((int[]){__VA_ARGS__}) / sizeof(int) > 0 ? __VA_ARGS__ : 0)

// malloc flags
#define GC_DEFAULT 0


typedef struct s_gc_node {
    void *ptr;
    struct s_gc_node *next;
} t_gc_node;

typedef struct s_gc {
    int flag;
    struct s_gc_node *head;
    struct s_gc*next;
} t_gc;



void *ft_malloc_(size_t size, int flag);
void ft_free(int flag);
void free_all();
void add_garbage(void *ptr, int flag);
void clear_garbage();