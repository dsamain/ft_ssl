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
    char *triplet = tlv_triplet(id, len);
    char *ret = ft_malloc(len + strlen(triplet));
    ft_memcpy(ret, triplet, strlen(triplet));
    ft_memcpy(ret + strlen(triplet), data, len);
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