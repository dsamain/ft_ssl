#pragma once

#include <stdlib.h>

#define PUT(x) write(1, x, ft_strlen(x))
#define PUT_ERR(x) write(2, x, ft_strlen(x))
#define throw(x) {PUT_ERR(x); exit(1);}


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
