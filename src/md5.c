#include "../ft_ssl.h"

static u_int32_t R[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static u_int32_t K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                       0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                       0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                       0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                       0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                       0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                       0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                       0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                       0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};


#define F(B,C,D) ((B & C) | ((~B) & D))
#define G(B,C,D) ((B & D) | (C & (~D)))
#define H(B,C,D) (B ^ C ^ D)
#define I(B,C,D) (C ^ (B | (~D)))

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
        ret[tot - 8 + i] = (sz >> (i * 8)) & 0xff;
    *len = tot;
    return ret;
}

char *md5(char *s) {
    u_int32_t ret[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}; // default values for md5
    size_t len;
    u_int8_t *t = padding(s, &len);

    while (len) {
        u_int32_t w[16] = {0};
        for (int i = 0; i < 16; i++)
            w[i] = t[i * 4 + 3] << 24 | t[i * 4 + 2] << 16 | t[i * 4 + 1] << 8 | t[i * 4];

        u_int32_t a = ret[0];
        u_int32_t b = ret[1];
        u_int32_t c = ret[2];
        u_int32_t d = ret[3];
        u_int32_t j, l;

        for (int i = 0; i < 64; i++) {
            if (i < 16) {
                j = F(b,c,d);
                l = i;
            } else if (i < 32) {
                j = G(b,c,d);
                l = (5 * i + 1) % 16;
            } else if (i < 48) {
                j = H(b,c,d);
                l = (3 * i + 5) % 16;
            } else {
                j = I(b,c,d);
                l = (7 * i) % 16;
            }
            u_int32_t tmp = d;
            d = c;
            c = b;
            b = left_rotate((a + j + K[i] + w[l]), R[i]) + b;
            a = tmp;
        }

        ret[0] += a;
        ret[1] += b;
        ret[2] += c;
        ret[3] += d;

        t += 64;
        len -= 64;
    }

    u_int8_t *result = ft_malloc(16);
    for (int i = 0; i < 4; i++) {
        result[i * 4 + 0] = (ret[i] & 0xff);
        result[i * 4 + 1] = (ret[i] & 0xff00) >> 8;
        result[i * 4 + 2] = (ret[i] & 0xff0000) >> 16;
        result[i * 4 + 3] = (ret[i] & 0xff000000) >> 24;
    }

    return result;
}
