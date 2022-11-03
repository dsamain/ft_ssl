#include "../../ft_ssl.h"

char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void decrypt_base64(t_cipher_args *args, int flags) {
    args->text_len--;
    if (args->text_len % 4 != 0)
        throw("invalid base64 input for decrypt\n");

    for (int i = 0; i < args->text_len / 4; i++) {
        u_int32_t cur = 0, cnt = 0;
        for (int j = 0; j < 4; j++) {
            cur = (cur << 6);
            if (args->text[i * 4 + j] != '=') {
                cur |= (ft_strchr(base, args->text[i * 4 + j]) - base);
            } else {
                cnt++;
            }
        }
        //printf("cnt : %d\n", cnt);
        for (int j = 0; j < 3 - cnt; j++) {
            char c = (cur >> (16 - j * 8)) & 0xff;
            write(args->out_fd, &c, 1);
        }
    }
}

void encrypt_base64(t_cipher_args *args, int flags) {
    int cnt = 0;

    for (int i = 0; i < args->text_len / 3 + !!(args->text_len % 3); i++) {
        u_int32_t cur = args->text[i * 3] << 16 | args->text[i * 3 + 1] << 8 | args->text[i * 3 + 2];
        u_int8_t padding = 0;
        if (i == args->text_len / 3)
            padding = (args->text_len % 3 == 1 ? 2 : 1);

        for (int j = 0; j < 4 - padding; j++, cnt++) {
            int idx = (cur >> (18 - j * 6)) & 0x3f;
            write(args->out_fd, &base[idx], 1);
            if (cnt % 64 == 63)
                write(args->out_fd, &"\n", 1);
        }
        for (int j = 0; j < padding; j++, cnt++) {
            write(args->out_fd, &"=", 1);
            if (cnt % 64 == 63)
                write(args->out_fd, &"\n", 1);
        }
    }
    if (cnt % 64) {
        write(args->out_fd, &"\n", 1);
    }
}

void base64(t_cipher_args *args, int flags) {
    if (!(flags & FLAG_I)) {
        args->text = read_fd(0, &args->text_len);
    }

    if (flags & FLAG_D) {
        decrypt_base64(args, flags);
    } else {
        encrypt_base64(args, flags);
    }
}