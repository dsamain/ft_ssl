#include "../ft_ssl.h"

u_int8_t *padding(char *s, size_t *len) {
    u_int64_t sz = ft_strlen(s);
    u_int32_t tot = sz + 9; // 8 bits fot the size + 1 bit for the 1
    tot += (tot % 64) ? (64 - tot % 64) : 0;

    u_int8_t *ret = ft_malloc(tot + 1);
    for (int i = 0; i < tot; i++)
        ret[i] = (i < sz ? s[i] : 0);

    ret[sz] = 0x80; // 1 at the end of the message
    // size in little endian at the end
    sz *= 8;

    for (int i = 0; i < 8; i++)
        ret[tot - i - 1] = (sz >> (i * 8)) & 0xff;

    *len = tot;
    return ret;
}

u_int8_t *padding_512(char *s, size_t *len) {
    u_int64_t sz = ft_strlen(s);
    u_int64_t tot = sz + 17; // 8 bits fot the size + 1 bit for the 1
    tot += (tot % 128) ? (128 - tot % 128) : 0;

    u_int8_t *ret = ft_malloc(tot + 1);
    for (int i = 0; i < tot; i++)
        ret[i] = (i < sz ? s[i] : 0);

    ret[sz] = 0x80; // 1 at the end of the message
    // size in little endian at the end
    sz *= 8;

    for (int i = 0; i < 8; i++)
        ret[tot - i - 1] = (sz >> (i * 8)) & 0xff;

    *len = tot;
    return ret;
}