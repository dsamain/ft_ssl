#include "gc.h"

int ft_strlen(char *s);

t_gc *g_garbage = NULL;

void *ft_malloc_(size_t size, int flag) {
    void *ret = malloc(size);
    if (!ret) throw("malloc error");
    add_garbage(ret, flag);
    return ret;
}

void ft_free(int flag) {
    t_gc *gc = g_garbage;
    while (gc) {
        if (gc->flag == flag) {
            t_gc_node *node = gc->head;
            while (node) {
                t_gc_node *tmp = node;
                node = node->next;
                free(tmp->ptr);
                free(tmp);
            }
            gc->head = NULL;
        }
        gc = gc->next;
    }
}

void free_all() {
    t_gc *gc = g_garbage;
    while (gc) {
        t_gc_node *node = gc->head;
        t_gc *tmp_gc = gc;
        while (node) {
            t_gc_node *tmp = node;
            node = node->next;
            free(tmp->ptr);
            free(tmp);
        }
        gc->head = NULL;
        gc = gc->next;
        free(tmp_gc);
    }
}

void add_garbage(void *ptr, int flag) {
    t_gc *cur = g_garbage, *prev = NULL;
    while (cur && cur->flag != flag) {
        prev = cur;
        cur = cur->next;
    }

    // create new garbage
    if (!cur) {
        cur = malloc(sizeof(t_gc));
        if (!cur) throw("malloc error");
        *cur = (t_gc){.flag = flag, .head = NULL, .next = NULL};

        if (!prev) {
            g_garbage = cur;
        } else {
            prev->next = cur;
        }
    }  

    // add ptr to garbage
    t_gc_node *new_node = malloc(sizeof(t_gc));
    if (!new_node) throw("malloc error");
    *new_node = (t_gc_node){.ptr = ptr, .next = NULL};
    if (cur->head)
        new_node->next = cur->head;
    cur->head = new_node;

}