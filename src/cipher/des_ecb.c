#include "../../ft_ssl.h"

#define at(x, n) (((x) >> n) & 1)
#define assign(x, shift, val) (x = (x & ~((u_int64_t)1 << i)) ^ ((u_int64_t)val << shift))

u_int8_t keyp[56] = { 57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34,
                      26, 18, 10, 2,  59, 51, 43, 35, 27, 19, 11, 3,
                      60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,
                      62, 54, 46, 38, 30, 22, 14, 6,  61, 53, 45, 37,
                      29, 21, 13, 5,  28, 20, 12, 4 };

void permute(int8_t *data, int8_t *perm, int size) {
    for (int i = 0; i < size; i++) {
        int8_t tmp = data[i];
        while (perm[i] >= 0) {
            data[i] = perm[perm[i] - 1] >= 0 ? data[perm[i] - 1] : tmp;
            perm[i] *= -1;
            i = -perm[i] - 1;
        }
    }
    for (int i = 0; i < size; i++) 
        perm[i] *= -1;
}

void permute_u64(u_int64_t *n, int8_t *perm, int size) {
    for (int i = 0; i < size; i++) {
        int8_t tmp = at(*n, i);
        while (perm[i] >= 0) {
            if (perm[perm[i]-1] >= 0)
                assign(*n, i, at(*n, perm[i] - 1));
            else
                assign(*n, i, tmp);
            perm[i] *= -1;
            i = -perm[i] - 1;
        }
    }

    for (int i = 0; i < size; i++) 
        perm[i] *= -1;
} 

u_int8_t *des_ecb(t_cipher_args *args) {

    u_int64_t key = 0x8888;
    u_int8_t perm[64];
    for (int i = 0; i < 64; i++) {
        perm[i] = i + 2;
    }
    perm[63] = 1;
    putb(key);
    permute_u64(&key, perm, 64);
    PUT("\n");
    putb(key);


    //permute_in_place(num, p, 13);
    //for (int i = 0; i < 13; i++) {
        //printf("%d ", num[i]);
    //}

    printf("\n");
    
}
