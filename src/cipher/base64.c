#include "../../ft_ssl.h"

char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define BN_POS 76

void check_text(char *text, size_t text_len, int flags) {

    int cnt = 0;
    for (int i = 0; text_len; i++) {
        if (text[i] == '\n') {
            if (i == text_len - 1)
                break;
            if (cnt % BN_POS != 0)
                throw("invalid base64 input\n");
        } else if (!ft_strchr(base, text[i]) && text[i] != '=') {
            throw("invalid base64 input\n");
        } else {
            cnt++;
        }
    }

    if (cnt % 4 != 0)
        throw("invalid base64 input\n");
}

char *decrypt_base64(char *text, size_t text_len, int flags, size_t *ret_len) {

    check_text(text, text_len, flags);

    char *ret = ft_malloc(text_len * 4 / 3 + 1);
    int k = 0;

    int cur = 0, cnt = 0, pad = 0;
    for (int i = 0; i < text_len; i++) {
        if (text[i] == '\n') {
            continue;
        }
        cur <<= 6;
        if (text[i] != '=') {
            cur |= (ft_strchr(base, text[i]) - base);
        } else {
            pad++;
        }
        cnt++;
        if (cnt == 4) {
            for (int j = 0; j < 3 - pad; j++) {
                char c = (cur >> (16 - j * 8)) & 0xff;
                ret[k++] = c;
            }
            cur = 0, cnt = 0, pad = 0;
        }
    }
    ret[k] = 0;
    if (ret_len) *ret_len = k;
    return ret;
}

char *encrypt_base64(char *text, size_t text_len, int flags, size_t *ret_len) {
    int cnt = 0, k = 0;

    char *ret = ft_malloc((text_len + !!(text_len % 3)) * 4  + text_len / 64 + 10);

    for (int i = 0; i < text_len / 3 + !!(text_len % 3); i++) {
        u_int32_t cur = (unsigned char)text[i * 3] << 16 | (unsigned char)text[i * 3 + 1] << 8 | (unsigned char)text[i * 3 + 2];
        u_int8_t padding = 0;
        if (i == text_len / 3)
            padding = (text_len % 3 == 1 ? 2 : 1);

        for (int j = 0; j < 4 - padding; j++, k++, cnt++) {
            int idx = (cur >> (18 - j * 6)) & 0x3f;
            ret[k] = base[idx];
            if (cnt % BN_POS == BN_POS - 1) {
                ret[++k] = '\n';
            }
        }
        for (int j = 0; j < padding; j++, k++, cnt++) {
            ret[k] = '=';
            if (cnt % BN_POS == BN_POS - 1) {
                ret[++k] = '\n';
            }
        }
    }

    ret[k] = 0;

    if (ret_len) *ret_len = k;

    return ret;
}

void base64(t_cipher_args *args, int flags) {
    if (!(flags & FLAG_I))
        args->text = read_fd(0, &args->text_len);

    if (flags & FLAG_D) {
        size_t ret_len;
        char *ret = decrypt_base64(args->text, args->text_len, flags, &ret_len);
        for (int i = 0; i < ret_len; i++) {
            write(args->out_fd, ret + i, 1);
        }
    } else {
        char *ret = encrypt_base64(args->text, args->text_len, flags, NULL);
        for (int i = 0; ret[i]; i++) {
            write(args->out_fd, &ret[i], 1);
            if (ret[i] != '\n' && !ret[i + 1])
                write(args->out_fd, &"\n", 1);
        }
    }
}