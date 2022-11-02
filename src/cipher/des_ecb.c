#include "../../ft_ssl.h"

#define at(x, i, size) ((x >> (size - (i) - 1)) & 1)
#define assign(x, shift, val) (x = (x & ~((u_int64_t)1 << shift)) ^ ((u_int64_t)val << shift))

// circular left shift
#define c_left_shift(x, shift, size) (((x << shift) | (x >> (size - shift))) & ((1 << size) - 1))

u_int8_t key_p[56] = { 57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34,
                      26, 18, 10, 2,  59, 51, 43, 35, 27, 19, 11, 3,
                      60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,
                      62, 54, 46, 38, 30, 22, 14, 6,  61, 53, 45, 37,
                      29, 21, 13, 5,  28, 20, 12, 4 };

u_int8_t key_comp[48] = { 14, 17, 11, 24, 1,  5,  3,  28,
                         15, 6,  21, 10, 23, 19, 12, 4,
                         26, 8,  16, 7,  27, 20, 13, 2,
                         41, 52, 31, 37, 47, 55, 30, 40,
                         51, 45, 33, 48, 44, 49, 39, 56,
                         34, 53, 46, 42, 50, 36, 29, 32 };

u_int8_t shift_table[16] = { 1, 1, 2, 2, 2, 2, 2, 2,
						1, 2, 2, 2, 2, 2, 2, 1 };

u_int8_t initial_perm[64] = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44,
	                    36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22,
	                    14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57,
	                    49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35,
	                    27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13,
	                    5, 63, 55, 47, 39, 31, 23, 15, 7 };

u_int8_t final_perm[64] = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47,
		            15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22,
		            62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36,
		            4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11,
		            51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58,
		            26, 33, 1, 41, 9, 49, 17, 57, 25 };
        
u_int8_t exp_d[48] = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
	            8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

// s-boxes
u_int8_t s[8][4][16] = {
	{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5,
	9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6,
	12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2,
	11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2,
	4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
	{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12,
	0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0,
	1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13,
	1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1,
	3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },

	{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12,
	7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4,
	6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13,
	6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12,
	5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8,
	7, 4, 15, 14, 3, 11, 5, 2, 12 },
	{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11,
	12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7,
	2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7,
	13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6,
	10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
	{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13,
	0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0,
	15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7,
	8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7,
	1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
	{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14,
	7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1,
	13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12,
	3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12,
	9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
	{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5,
	10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3,
	5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7,
	14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8,
	1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
	{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5,
	0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5,
	6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14,
	2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7,
	4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
};

// Straight Permutation Table
u_int8_t per[32] = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23,
		        26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27,
		        3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };


void permute(int8_t *blocks, int8_t *perm, int size) {
    for (int i = 0; i < size; i++) {
        int8_t tmp = blocks[i];
        while (perm[i] >= 0) {
            blocks[i] = perm[perm[i] - 1] >= 0 ? blocks[perm[i] - 1] : tmp;
            perm[i] *= -1;
            i = -perm[i] - 1;
        }
    }
    for (int i = 0; i < size; i++) 
        perm[i] *= -1;
}

u_int64_t permute_u64(u_int64_t n, int8_t *perm, int in_size, int out_size) {
    u_int64_t res = 0;
    for (int i = 0; i < out_size; i++) {
        res <<= 1;
        res = (res | ((n >> (in_size - perm[i])) & 1));
    }
    return res;
} 

void key_gen(u_int64_t key, u_int64_t *rkeys) {
    key = permute_u64(key, key_p, 64, 56);

    u_int64_t l = (key >> (28)) & ((1 << 28) - 1);
    u_int64_t r = (key ) & ((1 << 28) - 1);

    for (int i = 0; i < 16; i++) {
        l = c_left_shift(l, shift_table[i], 28);
        r = c_left_shift(r, shift_table[i], 28);

        u_int64_t rkey = (l << 28) | r;

        rkey = permute_u64(rkey, key_comp, 56, 48);

        rkeys[i] = rkey;
    }
}

void text_to_blocks(char *text, size_t len, u_int64_t *blocks) {
    int i;
    for (i = 0; i < len / 8 ; i++)
        for (int j = 0; j < 8; j++)
            blocks[i] = (blocks[i] << 8) | text[i * 8 + j];

    // padding for last block
    for (int j = 0; j < 8; j++)
        blocks[i] = (blocks[i] << 8) | (len % 8 > j ? text[i * 8 + j] : 8 - len % 8);
}

u_int64_t encrypt(u_int64_t block, u_int64_t *rkeys) {

    // initial permutation
    block = permute_u64(block, initial_perm, 64, 64);

    u_int64_t l = (block >> (32)) & (((u_int64_t)1 << 32) - 1);
    u_int64_t r = block & (((u_int64_t)1 << 32) - 1);

    for (int i = 0; i < 16; i++) {
        u_int64_t r_exp = permute_u64(r, exp_d, 32, 48);
        r_exp &= ((u_int64_t)1 << 48) - 1;

        u_int64_t r_xor = r_exp ^ rkeys[i];
        r_xor &= ((u_int64_t)1 << 48) - 1;

        u_int64_t sbox_out = 0;
        for (int i = 0; i < 8; i++) {
            int row = 2 * at(r_xor, i * 6, 48) + at(r_xor, i * 6 + 5, 48);
            int col = 8 * at(r_xor, i * 6 + 1, 48) 
                    + 4 * at(r_xor, i * 6 + 2, 48) 
                    + 2 * at(r_xor, i * 6 + 3, 48) 
                    + at(r_xor, i * 6 + 4, 48);
            int val = s[i][row][col];
            sbox_out = (sbox_out << 4) | val;
        }

		sbox_out = permute_u64(sbox_out, per, 32, 32);
        sbox_out &= ((u_int64_t)1 << 32) - 1;


		// XOR left and op
		r_xor = sbox_out ^ l;

		l = r_xor;

		// Swapper
		if (i != 15) {
            u_int64_t tmp = l;
            l = r;
            r = tmp;
		}
    }

    u_int64_t res = (l << 32) | r;

    res = permute_u64(res, final_perm, 64, 64);

    return res;

}

void show_cipher(u_int64_t *blocks, int len, int fd) {
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < 8; j++) {
            char c = (blocks[i] >> (56 - j * 8)) & 0xff;
            write(fd, &c, 1);
            //printf("%c",(blocks[i] >> (56 - j * 8)));
        }
        //put_hex_n(blocks[i], 64);
        //PUT(" ");
    }
    PUT("\n");
}

u_int8_t *des_ecb(t_cipher_args *args, int flags) {

    printf("key : %ld\n", args->key);

    u_int64_t rkeys[16];
    key_gen(args->key, rkeys);

    if (flags & FLAG_D) {
        printf("yes\n");
        for (int i = 0; i < 16 / 2; i++) {
            u_int64_t tmp = rkeys[i];
            rkeys[i] = rkeys[15 - i];
            rkeys[15 - i] = tmp;
        }
    }

    size_t text_len = ft_strlen(args->text);
    size_t blocks_len = text_len / 8 + 1;

    u_int64_t blocks[blocks_len];
    text_to_blocks(args->text, text_len, blocks);

    //blocks[0] = 5076063491319685041LL;
    //blocks[0] = 1499456985431636477LL;

    //for (int i = 0; i < 8; i++) {
        //u_int64_t tmp = rkeys[i];
        //rkeys[i] = rkeys[16 - i - 1];
        //rkeys[16 - i - 1] = tmp;
    //}

    for (int i = 0; i < blocks_len; i++) {
        blocks[i] = encrypt(blocks[i], rkeys);
    }

    PUT("cipher text: ");
    show_cipher(blocks, blocks_len, args->out_fd);
    //printf("Raw : %ld\n", blocks[0]);

    printf("\n");
    
}
