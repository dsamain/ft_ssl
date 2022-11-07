#include "../ft_ssl.h"
#include <stdarg.h>

int ft_strlen(char *s) {
    int i = 0;
    while (s && s[i]) 
        i++;
    return i;
}

char *ft_join(char *s, char *t) {
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

char *ft_join_len(char *s, size_t s_len, char *t, size_t t_len) {
    char *ret = ft_malloc(s_len + t_len + 1);

    for (int i = 0; i < s_len; i++) 
        ret[i] = s[i];
    for (int i = 0; i < t_len; i++) 
        ret[i + s_len] = t[i];
    ret[s_len + t_len] = 0;
    return ret;

}

char *cat_f(char *s, ...) {
    va_list l;
    va_start(l, s);
    char *tmp = NULL;
    do {
        s = ft_join(s, tmp);
    } while ((tmp = va_arg(l, char *)));
    va_end(l);
    return s;
}

int ft_strcmp(char *s, char *t) {
    int i;
    for (i = 0; s[i]; i++)
        if (s[i] != t[i])
            break;
    return (s[i] - t[i]); 
}

int ft_strncmp(char *s, char *t, int n) {
    int i;
    for (i = 0; s[i] && i < n; i++)
        if (s[i] != t[i])
            break;
    return (i == n ? 0 : s[i] - t[i]); 
}

char ft_tolower(char c) {
    if (c >= 'A' && c <= 'Z')
        return c + 32;
}

char *str_to_upper(char *s) {
    char *ret = ft_join(s, NULL);
    for (int i = 0; ret[i]; i++) {
        ret[i] += (ret[i] >= 'a' && s[i] <= 'z') * (-32);
    }
    return ret;
}

char *ft_strchr(char *s, char c) {
    for (int i = 0; s[i]; i++)
        if (s[i] == c)
            return s + i;
    return NULL;
}
