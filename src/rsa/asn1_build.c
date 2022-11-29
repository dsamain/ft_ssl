#include "rsa.h"


t_asn1_arg ull_to_arg(u_int64_t n) {
    t_asn1_arg arg = {0, 0};
    int log = 0;
    while (((__uint128_t)1 << log + 1) <= n)
        log++;
    arg.len = log / 8 + 1;
    arg.data = ft_malloc(arg.len);
    while (log >= 0) {
        arg.data[arg.len - log - 1] = (n >> (log * 8)) & 0xFF;
        log--;
    }
    return arg;
}

t_asn1_arg *build_tlv_len(t_asn1_arg args, int id) {

    size_t bytes = 1, start = 1, i;
    u_int8_t offset = 0;
    if (*args.data >> 7) {
        args.len++;
    }

    if (args.len > 127)
        while (args.len >> (bytes * 8))
            bytes++; 
    
    if (args.data[0] >> 7)
        offset = 1;

    t_asn1_arg *ret = ft_malloc(sizeof(t_asn1_arg));
    ret->len = bytes + 1;
    ret->data = ft_malloc(ret->len);
    ret->data[0] = id;

    if (bytes != 1)
        ret->data[start++] = (1 << 7) | bytes;

    for (i = 0; i < bytes; i++)
        ret->data[start + i] = ((args.len >> ((bytes - i - 1)) * 8) & 0xff);
    ret->data[start + i] = 0;

    return ret;
}

t_asn1_arg *build_tlv_def(t_asn1_arg args, int id) {
    t_asn1_arg *ret = build_tlv_len(args, id);
    if (*args.data >> 7) {
        ret->data = ft_join_len(ret->data, ret->len, "\0", 1);
        ret->len++;
    }
    ret->data = ft_join_len(ret->data, ret->len, args.data, args.len);
    ret->len += args.len;
    return ret;
}

t_asn1_arg *build_tlv_bs(t_asn1_arg args, int id) {
    args.len++;
    t_asn1_arg *ret = build_tlv_len(args, id);
    args.len--;
    ret->data = ft_join_len(ret->data, ret->len, "\x00", 1);
    ret->len += 1;
    ret->data = ft_join_len(ret->data, ret->len, args.data, args.len);
    ret->len += args.len;
    return ret;
}

t_asn1_arg *build_tlv_null() {
    t_asn1_arg *ret = ft_malloc(sizeof(t_asn1_arg));
    ret->data = ft_join_len("\x05\x00", 2, "", 0);
    ret->len = 2;
    return ret;
}

int seq_i = 0;
t_asn1_arg *asn1_build_(char *format, void *void_args, int *idx) {
    va_list *args = (va_list *)void_args;
    t_asn1_arg *ret = ft_malloc(sizeof(t_asn1_arg));
    ret->data = 0, ret->len = 0;

    for (; format[*idx]; (*idx)++) {

        if (format[*idx] == '}' || !format[*idx])
            return ret;

        int id = 0;
        if ((id = !ft_strncmp(format + *idx, "SEQ", 3) ? ASN1_SEQUENCE : 0)
            || (id = !ft_strncmp(format + *idx, "BIT_STRING", 10) ? ASN1_BIT_STRING : 0)) {

            while (format[*idx] != '{') 
                (*idx)++;

            t_asn1_arg *tmp = asn1_build_(format, args, idx);
            tmp = (id == ASN1_SEQUENCE ? build_tlv_def(*tmp, id) : build_tlv_bs(*tmp, id));
            ret->data = ft_join_len(ret->data, ret->len, tmp->data, tmp->len);
            ret->len += tmp->len;
        } 

        if ((id = !ft_strncmp(format + *idx, "NUM", 3) ? ASN1_NUMBER : 0)
                || (id = !ft_strncmp(format + *idx, "OI", 2) ? ASN1_OI : 0)) {

            t_asn1_arg *tmp = build_tlv_def(va_arg(*args, t_asn1_arg), id);
            ret->data = ft_join_len(ret->data, ret->len, tmp->data, tmp->len);
            ret->len += tmp->len;

        } else if (!ft_strncmp(format + *idx, "NULL", 4)) {

            t_asn1_arg *tmp = build_tlv_null();
            ret->data = ft_join_len(ret->data, ret->len, tmp->data, tmp->len);
            ret->len += tmp->len;
        }
    }
    return ret;
}

// parse and build user defined asn1 pem format (see test_asn1_build)
char *asn1_build(char *format, ...) {
    va_list args;
    va_start(args, format);
    int idx = 0;
    t_asn1_arg *ret = asn1_build_(format, &args, &idx);
    va_end(args);
    char *b64 = encrypt_base64(ret->data, ret->len, NULL);
    return b64;
}

void test_asn1_build() {
    u_int64_t num = 4242;
    // NUM and OI are associated with variadics parameters in the order they appear
    char *asn1 = asn1_build( \
        "SEQ { \
            SEQ { \
                OI \
                NULL \
            } SEQ { \
                BIT_STRING { \
                    NUM \
                    NUM \
               } \
            }2 \
        }3",  (t_asn1_arg){"456", 3}, ull_to_arg(255), ull_to_arg(18446744073709551615ULL));
}