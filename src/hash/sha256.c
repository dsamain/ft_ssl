#include "../../ft_ssl.h"


#define ch(x, y, z) ((x & y) ^ (~x & z))
#define maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define usig0(x) (right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22))
#define usig1(x) (right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25))
#define lsig0(x) (right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3))
#define lsig1(x) (right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10))
#define ADD(x,y) ((x+y) & 0xffffffff)

static u_int32_t k[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
		0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
		0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
		0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
		0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
		0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
		0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
		0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
		0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

char *sha256(char *s, size_t sz) {
    u_int32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    size_t len;
    u_int8_t *padded = padding(s, sz, &len);

    while (len) {
        u_int32_t w[64];
        for (int i = 0; i < 64; i++) {
            if (i < 16)
                w[i] = (padded[i * 4 + 0] << 24) | (padded[i * 4 + 1] << 16) | (padded[i * 4 + 2] << 8) | (padded[i * 4 + 3]);
            else {
                w[i] = lsig1(w[i - 2]) + w[i - 7] + lsig0(w[i - 15]) + w[i - 16];
            }
        } 

        u_int32_t a = H[0];
        u_int32_t b = H[1];
        u_int32_t c = H[2];
        u_int32_t d = H[3];
        u_int32_t e = H[4];
        u_int32_t f = H[5];
        u_int32_t g = H[6];
        u_int32_t h = H[7];

        u_int32_t t1, t2;

        for (int i = 0; i < 64; i++) {
            t1 = h + usig1(e) + ch(e, f, g) + k[i] + w[i];
            t2 = usig0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;

        padded += 64;
        len -= 64;
    }
    u_int8_t *result = ft_malloc(32); 
    for (int i = 0; i < 8; i++) {
        result[i * 4 + 0] = (H[i] >> 24) & 0xff;
        result[i * 4 + 1] = (H[i] >> 16) & 0xff;
        result[i * 4 + 2] = (H[i] >> 8) & 0xff;
        result[i * 4 + 3] = (H[i]) & 0xff;
    }
    return (char *)result;
}