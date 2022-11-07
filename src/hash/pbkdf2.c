#include "../../ft_ssl.h"

#define SHA_256_BLOCK_SIZE 64
#define SHA_256_HASH_SIZE 32

// null termiated key / text
char *hmac_sha256(u_int8_t *text, size_t text_len, u_int8_t *key, size_t key_len) {
    u_int8_t *k;
    u_int8_t k_ipad[SHA_256_BLOCK_SIZE + 1]; /* inner padding - key XORd with ipad */
    u_int8_t k_opad[SHA_256_BLOCK_SIZE + 1]; /* outer padding - key XORd with opad */

    memset(k_ipad, 0x36, SHA_256_BLOCK_SIZE);
    memset(k_opad, 0x5c, SHA_256_BLOCK_SIZE);

    if (key_len > SHA_256_BLOCK_SIZE) {
        k = sha256(key, key_len);
        //put_hex(k, SHA_256_BLOCK_SIZE);
    } else {
        k = ft_malloc(SHA_256_BLOCK_SIZE); 
        memset(k, 0, SHA_256_BLOCK_SIZE);
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < SHA_256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }


    char *joined = ft_join_len(k_ipad, SHA_256_BLOCK_SIZE, text, text_len);
    u_int8_t *i_hash = sha256(joined, SHA_256_BLOCK_SIZE + text_len);

    joined = ft_join_len(k_opad, SHA_256_BLOCK_SIZE, i_hash, SHA_256_HASH_SIZE);
    u_int8_t *o_hash = sha256(joined, SHA_256_BLOCK_SIZE + SHA_256_HASH_SIZE);

    return o_hash;
}

#define SALT_LEN 8

char *pbkdf2(char *password, char *salt, int iterations, int key_len) {
    char *s = ft_join_len(salt, SALT_LEN, (char *)&key_len, 4);
    memset(s + SALT_LEN, 0, 4);
    s[SALT_LEN + 3] = 1;

    //return hmac_sha256(s, ft_strlen(salt) + 4, password, ft_strlen(password));
    char **u = ft_malloc(sizeof(char *) * iterations);
    u[0] = hmac_sha256(s, SALT_LEN + 4, password, ft_strlen(password));
    for (int i = 1; i < iterations; i++) {
        u[i] = hmac_sha256(u[i-1], 32, password, ft_strlen(password));
        //u[i] = hmac_sha256(password, ft_strlen(password), u[i-1], 32);
    }
    char *ret = ft_malloc(32);
    memset(ret, 0, 32);
    for (int i = 0; i < iterations; i++) {
        for (int j = 0; j < 32; j++) {
            ret[j] ^= u[i][j];
            //u[i][j] ^= u[i-1][j];
        }
    }
    return ret;
    //printf("s : \n");
    //put_hex(s, ft_strlen(s) + 4);
    //printf("\n");
    return s;
    //return hmac_sha256(s, ft_strlen(s) + 4, password, ft_strlen(password));
    //return hmac_sha256(password, ft_strlen(password), s, ft_strlen(salt) + 4);
}