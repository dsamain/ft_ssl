#include "../../ft_ssl.h"


#define ch(x, y, z) ((x & y) ^ (~x & z))
#define maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define usig0(x) (right_rotate_ll(x, 28) ^ right_rotate_ll(x, 34) ^ right_rotate_ll(x, 39))
#define usig1(x) (right_rotate_ll(x, 14) ^ right_rotate_ll(x, 18) ^ right_rotate_ll(x, 41))
#define lsig0(x) (right_rotate_ll(x, 1) ^ right_rotate_ll(x, 8) ^ (x >> 7))
#define lsig1(x) (right_rotate_ll(x, 19) ^ right_rotate_ll(x, 61) ^ (x >> 6))

static u_int64_t k[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
	};

char *sha512(char *s) {
    u_int64_t H[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    size_t len;
    u_int8_t *padded = padding_512(s, &len);
    while (len) {
        u_int64_t w[80] = {0};
        for (int i = 0; i < 80; i++) {
            if (i < 16) {
                //w[i] = padded[i * 8] << 56 | padded[i * 8 + 1] << 48 | padded[i * 8 + 2] << 40 | padded[i*8 + 3] << 32 | padded[i*8 + 4] << 24 | padded[i*8 + 5] << 16 | padded[i*8 + 6] << 8 | padded[i*8 + 7];
                w[i] = 0;
                for (int j = 0; j < 8; j++)
                    w[i] |= (u_int64_t)(padded[i * 8 + j] & 0xff) << (56 - j * 8);
            }
                //w[i] = (padded[i * 4 + 0] << 24) | (padded[i * 4 + 1] << 16) | (padded[i * 4 + 2] << 8) | (padded[i * 4 + 3]);
            else {
                w[i] = lsig1(w[i - 2]) + w[i - 7] + lsig0(w[i - 15]) + w[i - 16];
            }
        } 

        u_int64_t a = H[0];
        u_int64_t b = H[1];
        u_int64_t c = H[2];
        u_int64_t d = H[3];
        u_int64_t e = H[4];
        u_int64_t f = H[5];
        u_int64_t g = H[6];
        u_int64_t h = H[7];

        u_int64_t t1, t2;

        for (int i = 0; i < 80; i++) {
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

        padded += 128;
        len -= 128;
    }
    u_int8_t *result = ft_malloc(64); 
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++)
            result[i * 8 + j] = (H[i] >> (56 - j * 8)) & 0xff;
        //result[i * 4 + 0] = (H[i] >> 24) & 0xff;
        //result[i * 4 + 1] = (H[i] >> 16) & 0xff;
        //result[i * 4 + 2] = (H[i] >> 8) & 0xff;
        //result[i * 4 + 3] = (H[i]) & 0xff;
        //result[i * 4 + 3] = (H[i]) & 0xff;
        //result[i * 4 + 3] = (H[i]) & 0xff;
        //result[i * 4 + 3] = (H[i]) & 0xff;
        //result[i * 4 + 3] = (H[i]) & 0xff;
    }
    return result;
}