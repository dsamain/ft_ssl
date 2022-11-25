#include "rsa.h"

typedef struct s_asn1_arg {
    char *data;
    size_t len;
} t_asn1_arg;

//char *asn1 = asn1_build("SEQ { 
                            //NUM $ NUM $
                        //}", t_asn1_arg{"123", 3}, t_asn1_arg{"456", 3});
t_asn1_arg *build_tlv(t_asn1_arg args, int id) {

    dbg("tlv called for %x\n", id);
    dbg("args.data = %s\n", args.data);

    size_t bytes = 1, start = 1, i;

    u_int8_t offset = 0;

    if (args.len > 127) {
        //len ^= (1 << 7);
        while (args.len >> (bytes * 8))
            bytes++; 
    }
    t_asn1_arg *ret = ft_malloc(sizeof(t_asn1_arg));
    ret->len = bytes + 1;
    ret->data = ft_malloc(ret->len);

    ret->data[0] = id;

    // if len > 127, first byte is 0x80 + number of bytes
    if (bytes != 1)
        ret->data[start++] = (1 << 7) | bytes;

    for (i = 0; i < bytes; i++)
        ret->data[start + i] = ((args.len >> ((bytes - i - 1)) * 8) & 0xff);

    ret->data[start + i] = 0;
    dbg("ret->data : \n");
    put_hex_fd(ret->data, ret->len, 2);
    dbg("\n");
    dbg("args.data : \n");
    put_hex_fd(args.data, args.len, 2);
    dbg("\n");

    ret->data = ft_join_len(ret->data, ret->len, args.data, args.len);
    ret->len += args.len;

    {
        char *b64 = encrypt_base64(ret->data, ret->len, NULL);
        //dbg("tlv returns %s\n", b64);
        dbg("ret:\n");
        put_hex_fd(ret->data, ret->len, 2);
        dbg("\n");
    }
    return ret;
}

t_asn1_arg *asn1_build_(char *format, void *void_args, int *idx) {
    va_list *args = (va_list *)void_args;
    //printf("args : %s\n", va_arg(*args, t_asn1_arg).data);
    t_asn1_arg *ret = ft_malloc(sizeof(t_asn1_arg));
    for (; format[*idx]; (*idx)++) {
        //dbg("idx : %d\n", *idx);
        //dbg("format : %s\n", format + *idx);
        //dbg("ft_strncmp : %d\n", ft_strncmp(format + *idx, "SEQ", 3));
        if (format[*idx] == '}') {
            *idx++;
            return ret;
        } 
        if (!ft_strncmp(format + *idx, "SEQ", 3)) {
            dbg("SEQ found\n");
            while (format[(*idx)++] != '{')
                ;
            t_asn1_arg *tmp = asn1_build_(format, args, idx);
            ret->data =  ft_join_len(ret->data, ret->len, tmp->data, tmp->len);
        }
        int id = 0;
        if ((id = !ft_strncmp(format + *idx, "NUM", 3) ? ASN1_NUMBER : id),
                (id = !ft_strncmp(format + *idx, "OI", 2) ? ASN1_OI : id)) {
            dbg("NUM found\n");
            t_asn1_arg *tmp = build_tlv(va_arg(*args, t_asn1_arg), id);
            ret->data = ft_join_len(ret->data, ret->len, tmp->data, tmp->len);
            ret->len += tmp->len;
        }
    }
}

char *asn1_build(char *format, ...) {
    va_list args;
    va_start(args, format);
    int idx = 0;
    t_asn1_arg *ret = asn1_build_(format, &args, &idx);
    va_end(args);
    char *b64 = encrypt_base64(ret->data, ret->len, NULL);
    dbg("b64 : %s\n", b64);
    return ret->data;
}

void test_asn1_build() {
    u_int64_t num = 4242;
    char *asn1 = asn1_build( \
        "SEQ { \
            SEQ { \
                OI \
                NL \
            } BIT_STRING { \
                SEQ {  \
                    NUM \
                    NUM \
                } \
            } \
        }", (t_asn1_arg){"123", 3}, (t_asn1_arg){"456", 3}, (t_asn1_arg){ft_to_str(&num, 8), 8}, (t_asn1_arg){"123", 3}, (t_asn1_arg){"456", 3}); 
}