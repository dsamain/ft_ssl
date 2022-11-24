#include "rsa.h"

// tlv_triplet : [id, len, value]
char *tlv_triplet(u_int8_t id, u_int32_t len) {
    size_t bytes = 1, start = 1, i;

    if (len > 127) {
        //len ^= (1 << 7);
        while (len >> (bytes * 8))
            bytes++; 
    }
    dbg("len : %d\n", len);
    dbg("bytes : %ld\n", bytes);
    char *triplet = ft_malloc(bytes + 2);

    triplet[0] = id;

    // if len > 127, first byte is 0x80 + number of bytes
    if (bytes != 1)
        triplet[start++] = (1 << 7) | bytes;

    for (i = 0; i < bytes; i++)
        triplet[start + i] = ((len >> ((bytes - i - 1)) * 8) & 0xff);

    triplet[start + i] = 0;
    return triplet;
}

char *asn1_type(u_int8_t id, char *data, u_int8_t len, int *ret_len) {
    u_int8_t offset = 0;

    if ((data[0] >> 7) & 1)
        offset = 1;

    char *triplet = tlv_triplet(id, len);
    char *ret = ft_malloc(len + strlen(triplet) + offset);

    ft_memcpy(ret, triplet, strlen(triplet));
    ft_memcpy(ret + strlen(triplet) + offset, data, len);

    if (offset)
        ret[strlen(triplet)] = 0;

    *ret_len = len + strlen(triplet);

    return ret;
}

void check_asn1_id(u_int8_t data, u_int8_t id) {
    if (id != data)
        throw("wrong asn1 id\n");
}

void append_asn1_number(char *ret, size_t *idx, char *data, size_t data_len) {
    int elem_len;
    char *elem = asn1_type(ASN1_NUMBER, data, data_len, &elem_len);
    ft_memcpy(ret + *idx, elem, elem_len); 
    *idx += elem_len; 
}

// Convert key to asn1-pem format
// https://mbed-tls.readthedocs.io/en/latest/kb/cryptography/asn1-key-structures-in-der-and-pem/
char *rsa_key_pem_64(t_rsa_key *key)
{
    char *ret = ft_malloc(sizeof(int) * 100);
    size_t idx = 2;

    // SEQUENCE (9 elem) : [version, n, e, d, p, q, d1, d2, qinv]
    append_asn1_number(ret, &idx, "\0", 1);
    append_asn1_number(ret, &idx, ft_to_str(&key->n, 8), 8);
    append_asn1_number(ret, &idx, ft_to_str(&key->e, 8), 8);
    append_asn1_number(ret, &idx, ft_to_str(&key->d, 8), 8);
    append_asn1_number(ret, &idx, ft_to_str(&key->p, 8), 8);
    append_asn1_number(ret, &idx, ft_to_str(&key->q, 8), 8);
    append_asn1_number(ret, &idx, ft_to_str(&key->d1, 8), 8);
    append_asn1_number(ret, &idx, ft_to_str(&key->d2, 8), 8);
    append_asn1_number(ret, &idx, ft_to_str(&key->qinv, 8), 8);

    // Sequence tlv
    ft_memcpy(ret, tlv_triplet(ASN1_SEQUENCE, idx - 2), 2);

    return encrypt_base64(ret, idx, NULL);
}

size_t get_elem_len(u_int8_t *data, size_t *idx, size_t tot_len) {
    size_t byte_len = 1, len = 0;
    if (data[*idx] & (1 << 7)) {
        byte_len = data[*idx] & ~((u_int8_t)1 << 7);
        (*idx)++;
    }
    for (size_t i = 0; i < byte_len; i++, (*idx)++)
        len = (len << 8) | (u_int8_t)data[*idx];
    if (*idx + len > tot_len)
        throw("Invalid ASN.1 data");
    return len;
}

void get_asn1_number(u_int8_t *data, size_t *idx, u_int8_t **dest, size_t *dest_len, size_t data_len) {
    if (data[(*idx)++] != ASN1_NUMBER)
        throw("Can't parse key");
    *dest_len = get_elem_len(data, idx, data_len); 
    if (*dest_len + *idx > data_len)
        throw("Can't parse key");
    *dest = (u_int8_t *)ft_strndup((char *)data + *idx, *dest_len);
    *idx += *dest_len;
}

// SEQUENCE (2 elem)
  // SEQUENCE (2 elem)
    // OBJECT IDENTIFIER 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1)
    // NULL
  // BIT STRING (2160 bit) 001100001000001000000001000010100000001010000010000000010000000100000…
    // SEQUENCE (2 elem)
// Offset: 24
// Length: 4+266
// (constructed)
// Value:
// (2 elem)
      // INTEGER (2048 bit) 270948206434524864376531386076272800126502343643226434441426240139087…
      // INTEGER 65537

void asn1_private_to_public(t_rsa_private_asn1 *private_key) {
    // max size of ret : 2 (seq1) + 2(seq1.1)  + 11(oi) + 2(NULL) + bit string(seq(2) + integer(modulus) + integer(exponent))
    //char *ret = ft_malloc(size)
    char *pref = ft_malloc(17);
    //3023300D06092A864886F70D0101010500
    //30230d06092a864886f70d01010105000064%
    //30 23 30 0D 06 09 2A 86  48 86 F7 0D 01 01 01 05

    char *modulus = tlv_triplet(ASN1_NUMBER, private_key->modulus_len);
    size_t modul_len = ft_strlen(modulus) + private_key->modulus_len;

    modulus = ft_join_len(modulus, ft_strlen(modulus), (char *)private_key->modulus, private_key->modulus_len);

    char *exponent = tlv_triplet(ASN1_NUMBER, private_key->publicExponent_len);
    size_t exp_len = ft_strlen(exponent) + private_key->publicExponent_len;

    exponent = ft_join_len(exponent, ft_strlen(exponent), (char *)private_key->publicExponent, private_key->publicExponent_len);

    char *seq1 = tlv_triplet(ASN1_SEQUENCE, modul_len + exp_len);
    size_t seq1_len = ft_strlen(seq1);
    seq1 = ft_join_len(seq1, ft_strlen(seq1), modulus, modul_len);
    seq1_len += modul_len;
    seq1 = ft_join_len(seq1, seq1_len, exponent, exp_len);
    seq1_len += exp_len;

    char *bit_string = tlv_triplet(ASN1_BIT_STRING, seq1_len);
    size_t bit_len = ft_strlen(bit_string);
    bit_string = ft_join_len(bit_string, ft_strlen(bit_string), "\x00", 1);
    bit_len++;
    bit_string = ft_join_len(bit_string, bit_len, seq1, seq1_len);
    bit_len += seq1_len;


    char *obj_id = tlv_triplet(ASN1_OI, 9);
    size_t obj_len = ft_strlen(obj_id);
    obj_id = ft_join_len(obj_id, ft_strlen(obj_id), "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", 9);
    obj_len += 9;
    obj_id = ft_join_len(obj_id, obj_len, "\x05\x00", 2);
    obj_len += 2;

    char *seq2 = tlv_triplet(ASN1_SEQUENCE, obj_len);
    size_t seq2_len = ft_strlen(seq2);
    seq2 = ft_join_len(seq2, seq2_len, obj_id, obj_len);
    seq2_len += obj_len;

    char *ret = tlv_triplet(ASN1_SEQUENCE, bit_len + seq2_len);
    size_t ret_len = ft_strlen(ret);
    ret = ft_join_len(ret, ret_len, seq2, seq2_len);
    ret_len += seq2_len;
    ret = ft_join_len(ret, ret_len, bit_string, bit_len);
    ret_len += bit_len;

    PUT("oi:\n");
    put_hex_fd((u_int8_t *)obj_id, obj_len, 1);
    PUT("\n");

    PUT("seq2:\n");
    put_hex_fd((u_int8_t *)seq2, seq2_len, 1);
    PUT("\n");

    PUT("bit_string:\n");
    put_hex_fd((u_int8_t *)bit_string, bit_len, 1);
    PUT("\n");

    PUT("seq1:\n");
    put_hex_fd((u_int8_t *)seq1, seq1_len, 1);
    PUT("\n");

    PUT("--RET--\n");
    put_hex_fd((u_int8_t *)ret, ret_len, 1);
    PUT("\n");

    char *b64 = encrypt_base64(ret, ret_len, NULL);

    PUT("b64:\n");
    PUT(b64);
    PUT("\n");





    ft_memcpy(pref, "\x30\x23\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x00", 17);

    size_t size = private_key->modulus_len 
                + private_key->publicExponent_len
                + ft_strlen(tlv_triplet(ASN1_NUMBER, private_key->modulus_len)) 
                + ft_strlen(tlv_triplet(ASN1_NUMBER, private_key->publicExponent_len));
    dbg("size : %zu\n", size);
    dbg("bitstring size : %d \n", ft_strlen(tlv_triplet(ASN1_BIT_STRING, size)));
    size += ft_strlen(tlv_triplet(ASN1_BIT_STRING, size)) + 2; 


    dbg ("size : %zu\n", size + 17);




    //char *b64 = encrypt_base64(pref, 17, NULL);
    //dbg("b64 : %s\n", b64);
    //put_fd("pref :\n", 2);
    //put_hex((u_int8_t *)pref, 18);
    //(void)private_key;
}

u_int8_t *extract_data(char *content, size_t *start, size_t *len, char *header, char *footer) {
    if (ft_strncmp(content, header, ft_strlen(header)) != 0)
        throw("Invalid header\n");

    *start = ft_strlen(header), *len = 0;
    while (content[*start + *len] && ft_strncmp(content + *start + *len, footer, ft_strlen(footer)) != 0)
        (*len)++;

    if (!content[*start + *len])
        throw("Invalid footer\n");
    content[*start + *len] = 0;

    u_int8_t *data = (u_int8_t *)decrypt_base64(content + *start, *len, len);
    return data;
}


t_rsa_private_asn1 parse_private_key(t_rsa_args *args) {
    t_rsa_private_asn1 key = INIT_RSA_PRIVATE_ASN1;
    size_t start, data_len, idx = 0;
    u_int8_t *data = extract_data(args->content, &start, &data_len,
                    "-----BEGIN RSA PRIVATE KEY-----", 
                    "-----END RSA PRIVATE KEY-----");

    // SEQUENCE (9 elem)
    check_asn1_id(data[idx++], ASN1_SEQUENCE);
    get_elem_len(data, &idx, data_len);

    // NUMBERS : [version, n, e, d, p, q, d1, d2, iqmp]
    get_asn1_number(data, &idx, &key.version, &key.version_len, data_len);
    get_asn1_number(data, &idx, &key.modulus, &key.modulus_len, data_len);
    get_asn1_number(data, &idx, &key.publicExponent, &key.publicExponent_len, data_len);
    get_asn1_number(data, &idx, &key.privateExponent, &key.privateExponent_len, data_len);
    get_asn1_number(data, &idx, &key.prime1, &key.prime1_len, data_len);
    get_asn1_number(data, &idx, &key.prime2, &key.prime2_len, data_len);
    get_asn1_number(data, &idx, &key.exponent1, &key.exponent1_len, data_len);
    get_asn1_number(data, &idx, &key.exponent2, &key.exponent2_len, data_len);
    get_asn1_number(data, &idx, &key.coefficient, &key.coefficient_len, data_len);

    // -- DEBUG --
    PUT("version:\n");
    put_hex_fd(key.version, key.version_len, 1);
    PUT("\n");
    PUT("modulus:\n");
    put_hex_fd(key.modulus, key.modulus_len, 1);
    PUT("\n");
    PUT("publicExponent:\n");
    put_hex_fd(key.publicExponent, key.publicExponent_len, 1);
    PUT("\n");
    PUT("privateExponent:\n");
    put_hex_fd(key.privateExponent, key.privateExponent_len, 1);
    PUT("\n");
    PUT("prime1:\n");
    put_hex_fd(key.prime1, key.prime1_len, 1);
    PUT("\n");
    PUT("prime2:\n");
    put_hex_fd(key.prime2, key.prime2_len, 1);
    PUT("\n");
    PUT("exponent1:\n");
    put_hex_fd(key.exponent1, key.exponent1_len, 1);
    PUT("\n");
    PUT("exponent2:\n");
    put_hex_fd(key.exponent2, key.exponent2_len, 1);
    PUT("\n");
    PUT("coefficient:\n");
    put_hex_fd(key.coefficient, key.coefficient_len, 1);
    PUT("\n");

    return key;
}

t_rsa_public_asn1 parse_public_key(t_rsa_args *args) {
    t_rsa_public_asn1 key = INIT_RSA_PUBLIC_ASN1;
    size_t start, data_len, idx = 0;
    u_int8_t *data = extract_data(args->content, &start, &data_len,
                    "-----BEGIN PUBLIC KEY-----",
                    "-----END PUBLIC KEY-----" );

    // SEQUENCE (2 elem)
    check_asn1_id(data[idx++], ASN1_SEQUENCE);
    get_elem_len(data, &idx, data_len);

    // 1. SEQUENCE (2 elem) : [algo identifier, null]
    check_asn1_id(data[idx++], ASN1_SEQUENCE);
    get_elem_len(data, &idx, data_len);

    // 1.1 ALGO ID : should be 1.2.840.113549.1.1.1 ?
    check_asn1_id(data[idx++], ASN1_OI);
    size_t oid_len = get_elem_len(data, &idx, data_len);
    idx += oid_len;

    // 1.2 NULL
    check_asn1_id(data[idx++], ASN1_NULL);
    if (data[idx++]) throw("Can't parse public key4");
    
    // 2. BIT STRING [ sequence (2 elem) : [modulus, publicExponent] ])]
    check_asn1_id(data[idx++], ASN1_BIT_STRING);
    get_elem_len(data, &idx, data_len); 
    // number of unused bits in the last byte (should be 0)
    if (data[idx++] != 0) throw("Can't parse public key12");
    
    // 2.1 SEQUENCE : [ modulus, publicExponent ]
    check_asn1_id(data[idx++], ASN1_SEQUENCE);
    get_elem_len(data, &idx, data_len);

    // 2.1.1 INTEGER : modulus, 2.1.2 INTEGER : publicExponent
    get_asn1_number(data, &idx, &key.publicKey, &key.publicKey_len, data_len); // modulus ( public key)
    get_asn1_number(data, &idx, &key.publicExponent, &key.publicExponent_len, data_len); // public exponent

    PUT("public key:\n");
    put_hex_fd(key.publicKey, key.publicKey_len, 1);
    PUT("\n");

    PUT("public exponent:\n");
    put_hex_fd(key.publicExponent, key.publicExponent_len, 1);
    PUT("\n");
    return key;
}
