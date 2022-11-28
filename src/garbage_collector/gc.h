#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "../../io.h"

/*  ft_malloc keep tracks of malloced memory by grouping them based on an id
    A call of ft_free(id) will then free all the memory allocated with id */

// This macro set a default value for the id parameter of ft_malloc (same behaviour as would be 'ft_malloc(size_t x, int id = GC_DEFAULT_ID)' in c++)
#define ft_malloc(x, ...) sizeof((int[]){__VA_ARGS__}) / sizeof(int) > 1 ? ft_malloc_(x, GC_DEFAULT) : ft_malloc_(x, sizeof((int[]){__VA_ARGS__}) / sizeof(int) > 0 ? __VA_ARGS__ : 0)

#define throw(x) {free_all(); PUT_ERR("Error: "); PUT_ERR(x); exit(1);}

// Malloc id
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