#include "rsa.h"

char *tlv_triplet(u_int8_t id, u_int8_t len) {
    if ((len >> 7) & 1) {
        u_int8_t *triplet = ft_malloc(4);
        triplet[0] = id;
        triplet[1] = 0x81;
        triplet[2] = len;
        triplet[3] = 0;
        return (char *)triplet;
    } else {
        u_int8_t *triplet = ft_malloc(3);
        triplet[0] = id;
        triplet[1] = len;
        triplet[2] = 0;
        return (char *)triplet;
    }
}

char *asn1_type(u_int8_t id, char *data, u_int8_t len, int *ret_len) {
    u_int8_t offset = 0;
    if ((data[0] >> 7) & 1) {
        offset = 1;
    }
    char *triplet = tlv_triplet(id, len);
    char *ret = ft_malloc(len + strlen(triplet) + offset);
    ft_memcpy(ret, triplet, strlen(triplet));
    ft_memcpy(ret + strlen(triplet) + offset, data, len);
    if (offset)
        ret[strlen(triplet)] = 0;
    *ret_len = len + strlen(triplet);
    free(triplet);
    return ret;
}

// format key to asn.1 PEM with in order : version, n, e, d, p, q, d1, d2, iqmp
char *rsa_key_pem(t_rsa_key *key)
{
    char *ret = ft_malloc(sizeof(int) * 100), *elem;
    int idx = 2, elem_len = 0;

    elem = asn1_type(ASN1_NUMBER, "\0", 1, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);
    elem = asn1_type(ASN1_NUMBER, ft_to_str(&key->n, 8), 8, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);
    elem = asn1_type(ASN1_NUMBER, ft_to_str(&key->e, 8), 8, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);
    elem = asn1_type(ASN1_NUMBER, ft_to_str(&key->d, 8), 8, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);
    elem = asn1_type(ASN1_NUMBER, ft_to_str(&key->p, 8), 8, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);
    elem = asn1_type(ASN1_NUMBER, ft_to_str(&key->q, 8), 8, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);
    elem = asn1_type(ASN1_NUMBER, ft_to_str(&key->d1, 8), 8, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);
    elem = asn1_type(ASN1_NUMBER, ft_to_str(&key->d2, 8), 8, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);
    elem = asn1_type(ASN1_NUMBER, ft_to_str(&key->qinv, 8), 8, &elem_len);
    ft_memcpy(ret + idx, elem, elem_len); idx += elem_len; free(elem);

    ft_memcpy(ret, tlv_triplet(ASN1_SEQUENCE, idx - 2), 2); // sequence

    return encrypt_base64(ret, idx, NULL);
}

size_t get_elem_len(u_int8_t *data, int *idx) {
    size_t byte_len = 1, len = 0;
    if (data[*idx] & (1 << 7)) {
        byte_len = data[*idx] & ~((u_int8_t)1 << 7);
        (*idx)++;
    }
    for (size_t i = 0; i < byte_len; i++, (*idx)++)
        len = (len << 8) | (u_int8_t)data[*idx];
    return len;
}

void get_number(u_int8_t *data, int *idx, u_int8_t **dest, size_t *dest_len, size_t data_len) {
    if (data[(*idx)++] != ASN1_NUMBER)
        throw("Can't parse key");
    *dest_len = get_elem_len(data, idx); 
    if (*dest_len + *idx > data_len)
        throw("Can't parse key");
    *dest = (u_int8_t *)ft_strndup((char *)data + *idx, *dest_len);
    *idx += *dest_len;
}

t_rsa_private_asn1 parse_private_key(t_rsa_args *args) {
    t_rsa_private_asn1 key = INIT_RSA_PRIVATE_ASN1;

    if (ft_strncmp(args->content, "-----BEGIN RSA PRIVATE KEY-----", 31) != 0)
        throw("Expected RSA private key");

    int start = 31, len = 0;
    while (args->content[start + len] && args->content[start + len] != '-')
        len++;
    if (ft_strncmp(args->content + start + len, "-----END RSA PRIVATE KEY-----", 29) != 0)
        throw("Expected RSA private key");

    args->content[start + len] = 0;
    size_t data_len = 0;
    u_int8_t *data = (u_int8_t *)decrypt_base64(args->content + start, len, &data_len);

    int idx = 0;

    if (data[idx++] != ASN1_SEQUENCE)
        throw("Can't parse private key");

    size_t seq_len = get_elem_len(data, &idx);

    dbg("idx seq data : %d %ld %ld\n", idx, seq_len, data_len);
    if (seq_len != data_len - idx)
        throw("Can't parse private key");

    get_number(data, &idx, &key.version, &key.version_len, data_len);
    PUT("version:\n");
    put_hex_fd(key.version, key.version_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.modulus, &key.modulus_len, data_len);
    PUT("modulus:\n");
    put_hex_fd(key.modulus, key.modulus_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.publicExponent, &key.publicExponent_len, data_len);
    PUT("publicExponent:\n");
    put_hex_fd(key.publicExponent, key.publicExponent_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.privateExponent, &key.privateExponent_len, data_len);
    PUT("privateExponent:\n");
    put_hex_fd(key.privateExponent, key.privateExponent_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.prime1, &key.prime1_len, data_len);
    PUT("prime1:\n");
    put_hex_fd(key.prime1, key.prime1_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.prime2, &key.prime2_len, data_len);
    PUT("prime2:\n");
    put_hex_fd(key.prime2, key.prime2_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.exponent1, &key.exponent1_len, data_len);
    PUT("exponent1:\n");
    put_hex_fd(key.exponent1, key.exponent1_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.exponent2, &key.exponent2_len, data_len);
    PUT("exponent2:\n");
    put_hex_fd(key.exponent2, key.exponent2_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.coefficient, &key.coefficient_len, data_len);
    PUT("coefficient:\n");
    put_hex_fd(key.coefficient, key.coefficient_len, 1);
    PUT("\n");

    return key;
}

t_rsa_public_asn1 parse_public_key(t_rsa_args *args) {
    t_rsa_public_asn1 key = INIT_RSA_PUBLIC_ASN1;

    if (ft_strncmp(args->content, "-----BEGIN PUBLIC KEY-----", 26) != 0)
        throw("Expected RSA public key");

    int start = 26, len = 0;
    while (args->content[start + len] && args->content[start + len] != '-')
        len++;
    if (ft_strncmp(args->content + start + len, "-----END PUBLIC KEY-----", 24) != 0)
        throw("Expected RSA public key5");

    args->content[start + len] = 0;
    size_t data_len = 0;
    u_int8_t *data = (u_int8_t *)decrypt_base64(args->content + start, len, &data_len);

    int idx = 0;

    // first seq
    if (data[idx++] != ASN1_SEQUENCE)
        throw("Can't parse public key4");

    size_t seq_len = get_elem_len(data, &idx);

    if (seq_len != data_len - idx)
        throw("Can't parse public key3");
    

    // second seq
    if (data[idx++] != ASN1_SEQUENCE)
        throw("Can't parse public key2");
    
    size_t seq_len2 = get_elem_len(data, &idx);
    if (idx + seq_len2 > data_len)
        throw("Can't parse public key1");

    if (data[idx++] != ASN1_OI)
        throw("Can't parse public key2");
    
    size_t oid_len = get_elem_len(data, &idx);
    if (idx + oid_len + 2 > data_len)
        throw("Can't parse public key3");
    
    idx += oid_len;

    if (data[idx++] != ASN1_NULL)
        throw("Can't parse public key4");
    if (data[idx++])
        throw("Can't parse public key4");
    
    if (data[idx++] != ASN1_BIT_STRING)
        throw("Can't parse public key5");

    size_t bit_len = get_elem_len(data, &idx); 
    if (data[idx++] != 0)
        throw("Can't parse public key12");
    if (idx + bit_len - 1 > data_len)
        throw("Can't parse public key6");
    
    dbg("IDX: %d\n", idx);
    if (data[idx++] != ASN1_SEQUENCE) 
        throw("Can't parse public key7");
    
    size_t seq_len3 = get_elem_len(data, &idx);
    dbg("seq_len3: %ld\n", seq_len3);
    if (idx + seq_len3 > data_len)
        throw("Can't parse public key8");

    get_number(data, &idx, &key.publicKey, &key.publicKey_len, data_len);
    PUT("public key:\n");
    put_hex_fd(key.publicKey, key.publicKey_len, 1);
    PUT("\n");

    get_number(data, &idx, &key.publicExponent, &key.publicExponent_len, data_len);
    PUT("public exponent:\n");
    put_hex_fd(key.publicExponent, key.publicExponent_len, 1);
    PUT("\n");
    //get_number(data, &idx, &key.coefficient, &key.coefficient_len, data_len);
    //PUT("coefficient:\n");
    //put_hex_fd(key.coefficient, key.coefficient_len, 1);
    //PUT("\n");



    //get_number(data, &idx, &key.version, &key.version_len, data_len);
    //PUT("version:\n");
    //put_hex_fd(key.version, key.version_len, 1);
    //PUT("\n");

    //get_number(data, &idx, &key.modulus, &key.modulus_len, data_len);
    //PUT("modulus:\n");
    //put_hex_fd(key.modulus, key.modulus_len, 1);
    //PUT("\n");
    return key;
}