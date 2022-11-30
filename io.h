#pragma once

#define DEBUG

#ifdef DEBUG
    #include <stdio.h>
    #include <string.h>
    #define dbg(...) {dprintf(2, "[%s:%d] ", __FILE__, __LINE__); dprintf(2, __VA_ARGS__);}
#else
    #define dbg(...)
#endif

// io 
#define PUT(x) write(1, x, ft_strlen(x))
#define put_fd(x, fd) write(fd, x, ft_strlen(x))
#define PUT_ERR(x) write(2, x, ft_strlen(x))
#define cat(...) (cat_f(__VA_ARGS__, NULL))