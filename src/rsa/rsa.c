#include "rsa.h"

//ft_ssl rsa [-inform PEM] [-outform PEM] [-in file] [-passin arg] [-out file] [-passout arg] [-des] [-
//text] [-noout] [-modulus] [-check] [-pubin] [-pubout]
void parse_rsa(int ac, char **av, t_rsa_args *args, int *flags){
    for (int i = 2; i < ac; i++) {
        if (!ft_strcmp("-inform", av[i])) {
            if (i == ac - 1)
                throw(cat("ft_ssl: rsa: option ", av[i], " requires an argument\n"));
            i++;
            *flags |= RSA_FLAG_INFORM;
            if (ft_strcmp("PEM", av[i]))
                throw(cat("ft_ssl: rsa: invalid format ", av[i], " for infile\n"));

        } else if (!ft_strcmp("-outform", av[i])) {
            if (i == ac - 1)
                throw(cat("ft_ssl: rsa: option ", av[i], " requires an argument\n"));
            i++;
            *flags |= RSA_FLAG_OUTFORM;
            if (ft_strcmp("PEM", av[i]))
                throw(cat("ft_ssl: rsa: invalid format ", av[i], " for outfile\n"));

        } else if (!ft_strcmp("-in", av[i])) {
            if (i == ac - 1)
                throw(cat("ft_ssl: rsa: option ", av[i], " requires an argument\n"));
            i++;
            *flags |= RSA_FLAG_IN;
            args->in_fd = open(av[i], O_RDWR);
            if (args->in_fd < 0)
                throw(cat("ft_ssl: rsa: ", av[i], ": No such file or directory\n"));
            args->content = (char *)read_fd(args->in_fd, &args->content_len);

        } else if (!ft_strcmp("-out", av[i])) {
            if (i == ac - 1)
                throw(cat("ft_ssl: rsa: option ", av[i], " requires an argument\n"));
            i++;
            *flags |= RSA_FLAG_OUT;
            args->out_fd = open(av[i], O_WRONLY | O_CREAT | O_TRUNC, 0644); 
            if (args->out_fd < 0)
                throw(cat("ft_ssl: rsa: ", av[i], ": can't open file\n"));

        } else if (!ft_strcmp("-text", av[i])) {
            *flags |= RSA_FLAG_TEXT;
            
        } else if (!ft_strcmp("-noout", av[i])) {
            *flags |= RSA_FLAG_NOOUT;
            
        } else if (!ft_strcmp("-modulus", av[i])) {
            *flags |= RSA_FLAG_MODULUS;
            
        } else if (!ft_strcmp("-pubin", av[i])) {
            *flags |= RSA_FLAG_PUBIN;
            
        } else if (!ft_strcmp("-pubout", av[i])) {
            *flags |= RSA_FLAG_PUBOUT;
            
        } else {
            throw(cat("ft_ssl: rsa: invalid option -- '", av[i], "'\n"));
        }
    }

    if ((*flags & RSA_FLAG_PUBIN) && !(*flags & RSA_FLAG_PUBOUT))
        throw("ft_ssl: rsa: public key input format specified but private key output format selected\n");
}

void show_text(char *s, u_int8_t *n, size_t len, int fd) {
    size_t len2 = len;
    put_fd(s, fd);
    __uint128_t cur = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i && i % 10 == len % 10)
            put_num_fd(cur, fd), cur = 0;
        cur = (cur << 8) | (i < len ? n[i] : 0);
    }
    put_fd(" (0x", fd);
    put_hex_fd(n, len2, fd);
    put_fd(")\n", fd);
}

void private_text(t_rsa_args *args, t_rsa_private_asn1 *key) {
    size_t tmp = 0;
    while (tmp < key->modulus_len && key->modulus[tmp] == 0)
        tmp++;
    tmp = key->modulus_len - tmp;
    put_fd("RSA Private-Key: (", args->out_fd);
    put_num_fd(tmp * 8, args->out_fd);
    put_fd(" bit, 2 primes)\n", args->out_fd);

    show_text("modulus: ", key->modulus, key->modulus_len, args->out_fd);
    show_text("publicExponent: ", key->publicExponent, key->publicExponent_len, args->out_fd);
    show_text("privateExponent: ", key->privateExponent, key->privateExponent_len, args->out_fd);
    show_text("prime1: ", key->prime1, key->prime1_len, args->out_fd);
    show_text("prime2: ", key->prime2, key->prime2_len, args->out_fd);
    show_text("exponent1: ", key->exponent1, key->exponent1_len, args->out_fd);
    show_text("exponent2: ", key->exponent2, key->exponent2_len, args->out_fd);
    show_text("coefficient: ", key->coefficient, key->coefficient_len, args->out_fd);
}

void public_text(t_rsa_args *args, t_rsa_public_asn1 *key) {
    size_t tmp = 0;
    while (tmp < key->publicKey_len && key->publicKey[tmp] == 0)
        tmp++;
    tmp = key->publicKey_len - tmp;
    put_fd("RSA Public-Key: (", args->out_fd);
    put_num_fd(tmp * 8, args->out_fd);
    put_fd(" bit, 2 primes)\n", args->out_fd);

    show_text("Modulus: ", key->publicKey, key->publicKey_len, args->out_fd);
    show_text("Exponent: ", key->publicExponent, key->publicExponent_len, args->out_fd);
}

void put_raw_key(char *key, size_t len, char *header, char *footer, int fd) {
    int i = 0;
    while (ft_strncmp(key + i, header, ft_strlen(header)))
        i++;
    i += ft_strlen(header);
    put_fd(header, fd);
    while (key[i]) {
        write(fd, key + i, 1);
        i++;
    }
    put_fd(footer, fd);
    put_fd("\n", fd);
    (void)len;
}

/* need to parse only header + data + footer */

void rsa(int ac, char **av) {
    t_rsa_args args = INIT_RSA_ARGS;
    int flags = 0;
    parse_rsa(ac, av, &args, &flags);
    if (!(flags & RSA_FLAG_IN))
        args.content = (char *)read_fd(0, &args.content_len);

    // key is private
    if (!(flags & RSA_FLAG_PUBIN)) {
        t_rsa_private_asn1 key = parse_private_key(&args);

        // private to public
        if (flags & RSA_FLAG_PUBOUT) {

            char *asn1 = asn1_build( \
                "SEQ { \
                    SEQ { \
                        OI \
                        NULL \
                    } BIT_STRING { \
                        SEQ { \
                            NUM \
                            NUM \
                        } \
                    } \
                }",  (t_asn1_arg){"\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01", 9}, 
                (t_asn1_arg){(char *)key.modulus, key.modulus_len}, 
                (t_asn1_arg){(char *)key.publicExponent, key.publicExponent_len});
            
            if (flags & RSA_FLAG_TEXT)
                private_text(&args, &key);
            
            if (flags & RSA_FLAG_MODULUS) {
                put_fd("Modulus=", args.out_fd);
                put_hex_fd(key.modulus, key.modulus_len, args.out_fd);
                put_fd("\n", args.out_fd);
            }
            PUT("writing RSA key\n");
            put_fd("-----BEGIN PUBLIC KEY-----\n", args.out_fd);
            put_fd(asn1, args.out_fd);
            put_fd("\n-----END PUBLIC KEY-----\n", args.out_fd);

        } else {
            if (flags & RSA_FLAG_TEXT)
                private_text(&args, &key);
            
            if (flags & RSA_FLAG_MODULUS) {
                put_fd("Modulus=", args.out_fd);
                put_hex_fd(key.modulus, key.modulus_len, args.out_fd);
                put_fd("\n", args.out_fd);
            }

            put_raw_key(args.content, args.content_len, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", args.out_fd);
            //for (int i = 0; i < args.content_len; i++)
                //write(args.out_fd, &args.content[i], args);
        }

    } else {
        t_rsa_public_asn1 key = parse_public_key(&args);

            if (flags & RSA_FLAG_TEXT)
                public_text(&args, &key);
            
            if (flags & RSA_FLAG_MODULUS) {
                put_fd("Modulus=", args.out_fd);
                put_hex_fd(key.publicKey, key.publicKey_len, 2);
                put_fd("\n", 2);
            }

        PUT("writing RSA key\n");
        put_raw_key(args.content, args.content_len, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----", args.out_fd);
    }
}

    
    
