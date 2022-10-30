#pragma once

#include <stdlib.h>
#include <stdarg.h>

#define PUT(x) write(1, x, ft_strlen(x))
#define PUT_ERR(x) write(2, x, ft_strlen(x))
#define throw(x) {PUT_ERR(x); exit(1);}
#define cat(...) (cat_f(__VA_ARGS__, NULL))

#define BUFF_SIZE 1024
#define FLAG_Q 1
#define FLAG_R 2


static inline int ft_strlen(char *s) {
    int i = 0;
    while (s && s[i]) 
        i++;
    return i;
}

static inline char *ft_join(char *s, char *t) {
    char *ret = malloc(ft_strlen(s) + ft_strlen(t) + 1);
    if (!ret) {
        throw("malloc error\n");
    }

    int i = 0;
    for (int j = 0; s && s[j]; j++, i++) 
        ret[i] = s[j];
    for (int j = 0; t && t[j]; j++, i++) 
        ret[i] = t[j];
    ret[i] = 0;
    return ret;
}

static inline char *cat_f(char *s, ...) {
    va_list l;
    va_start(l, s);
    char *tmp = NULL;
    do {
        s = ft_join(s, tmp);
    } while ((tmp = va_arg(l, char *)));
    va_end(l);
    return s;
}

static inline int ft_strcmp(char *s, char *t) {
    int i;
    for (i = 0; s[i]; i++)
        if (s[i] != t[i])
            break;
    return s[i] - t[i]; 
}

static inline char *to_upper(char *s) {
    char *ret = ft_join(s, NULL);
    for (int i = 0; ret[i]; i++) {
        ret[i] += (ret[i] >= 'a' && s[i] <= 'z') * (-32);
    }
    return ret;
}
