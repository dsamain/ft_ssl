#include "rsa.h"

void check_asn1_id(u_int8_t data, u_int8_t id) {
    if (id != data)
        throw("wrong asn1 id\n");
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

// NEED TO BE IMPROVED to 
u_int8_t *extract_data(char *content, size_t *start, size_t *len, char *header, char *footer) {
    int i = 0;
    while (content[*start + i] && ft_strncmp(content + *start + i, header, ft_strlen(header)))
        i++;
    if (!content[*start + i])
        throw("Can't find header\n");

    *start = i + ft_strlen(header), *len = 0;
    while (content[*start + *len] && ft_strncmp(content + *start + *len, footer, ft_strlen(footer)) != 0)
        (*len)++;
    if (!content[*start + *len])
        throw("Can't find footer\n");
    content[*start + *len] = 0;

    u_int8_t *data = (u_int8_t *)decrypt_base64(content + *start, *len, len);
    return data;
}


t_rsa_private_asn1 parse_private_key(t_rsa_args *args) {
    t_rsa_private_asn1 key = INIT_RSA_PRIVATE_ASN1;
    size_t start = 0, data_len = 0, idx = 0;
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
    //PUT("version:\n");
    //put_hex_fd(key.version, key.version_len, 1);
    //PUT("\n");
    //PUT("modulus:\n");
    //put_hex_fd(key.modulus, key.modulus_len, 1);
    //PUT("\n");
    //PUT("publicExponent:\n");
    //put_hex_fd(key.publicExponent, key.publicExponent_len, 1);
    //PUT("\n");
    //PUT("privateExponent:\n");
    //put_hex_fd(key.privateExponent, key.privateExponent_len, 1);
    //PUT("\n");
    //PUT("prime1:\n");
    //put_hex_fd(key.prime1, key.prime1_len, 1);
    //PUT("\n");
    //PUT("prime2:\n");
    //put_hex_fd(key.prime2, key.prime2_len, 1);
    //PUT("\n");
    //PUT("exponent1:\n");
    //put_hex_fd(key.exponent1, key.exponent1_len, 1);
    //PUT("\n");
    //PUT("exponent2:\n");
    //put_hex_fd(key.exponent2, key.exponent2_len, 1);
    //PUT("\n");
    //PUT("coefficient:\n");
    //put_hex_fd(key.coefficient, key.coefficient_len, 1);
    //PUT("\n");

    return key;
}

t_rsa_public_asn1 parse_public_key(t_rsa_args *args) {
    t_rsa_public_asn1 key = INIT_RSA_PUBLIC_ASN1;
    size_t start = 0, data_len, idx = 0;
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

    return key;
}
