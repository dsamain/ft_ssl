#include "rsa.h"

void check_rsautl_args(t_rsautl_args *args, int flags) {
    if (!(flags & RSA_FLAG_INKEY))
        throw("no keyfile specified\n");
    if ((flags & RSA_FLAG_DECRYPT) && (flags & RSA_FLAG_ENCRYPT))
        throw("only one of -encrypt or -decrypt may be specified\n");
    if ((flags & RSA_FLAG_DECRYPT) && (flags & RSA_FLAG_PUBIN))
        throw("cannot decrypt with public key\n");
}
 
//ft_ssl rsautl [-in file] [-out file] [-inkey file] [-pubin] [-encrypt] [-decrypt] [-hexdump]
t_rsautl_args parse_rsautl(int ac, char **av, int *flags) {
    t_rsautl_args ret = INIT_RSAUTL_ARGS;
    
    for (int i = 2; i < ac; i++) {
        if (!ft_strncmp(av[i], "-inkey", 6)) {
            if (i == ac - 1)
                throw("ft_ssl: rsautl: option requires an argument -- 'inkey'");
            i++;
            ret.inkey_fd = open(av[i], O_RDONLY);
            if (ret.inkey_fd < 0)
                throw(cat("ft_ssl: rsautl: ", av[i], ": No such file or directory"));
            ret.key = (char *)read_fd(ret.inkey_fd, &ret.key_len);
            *flags |= RSA_FLAG_INKEY;
        } else if (!ft_strncmp(av[i], "-in", 3)) {
            if (i == ac - 1)
                throw("ft_ssl: rsautl: option requires an argument -- 'in'");
            i++;
            ret.in_fd = open(av[i], O_RDONLY);
            if (ret.in_fd < 0)
                throw(cat("ft_ssl: rsautl: ", av[i], ": No such file or directory"));
            ret.content = (char *)read_fd(ret.in_fd, &ret.content_len);
            *flags |= RSA_FLAG_IN;
        } else if (!ft_strncmp(av[i], "-out", 4)) {
            if (i == ac - 1)
                throw("ft_ssl: rsautl: option requires an argument -- 'out'");
            i++;
            ret.out_fd = open(av[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (ret.out_fd < 0)
                throw(cat("ft_ssl: rsautl: ", av[i], ": No such file or directory"));
            *flags |= RSA_FLAG_OUT;
        } else if (!ft_strncmp(av[i], "-pubin", 6)) {
            *flags |= RSA_FLAG_PUBIN;
        } else if (!ft_strncmp(av[i], "-encrypt", 8)) {
            *flags |= RSA_FLAG_ENCRYPT;
        } else if (!ft_strncmp(av[i], "-decrypt", 8)) {
            *flags |= RSA_FLAG_DECRYPT;
        } else if (!ft_strncmp(av[i], "-hexdump", 8)) {
            *flags |= RSA_FLAG_HEXDUMP;
        } else {
            throw(cat("ft_ssl: rsautl: invalid option -- '", av[i], "'"));
        }
    }

    if (!(*flags & RSA_FLAG_DECRYPT))
        *flags |= RSA_FLAG_ENCRYPT;

    check_rsautl_args(&ret, *flags);

    return ret;
}

void get_exp_mod_msg(t_rsautl_args *args, int flags, u_int64_t *exp, u_int64_t *mod, u_int64_t *m) {
    char *exp_str = NULL, *mod_str = NULL;
    size_t exp_len = 0, mod_len = 0;
    t_rsa_args rsa_args = INIT_RSA_ARGS;
    rsa_args.content = args->key;
    if (flags & RSA_FLAG_PUBIN) {
        t_rsa_public_asn1 pub = parse_public_key(&rsa_args);
        exp_str = pub.publicExponent;
        exp_len = pub.publicExponent_len;
        mod_str = pub.publicKey;
        mod_len = pub.publicKey_len;
    } else {
        t_rsa_private_asn1 priv = parse_private_key(&rsa_args);
        if (flags & RSA_FLAG_ENCRYPT) {
            exp_str = priv.publicExponent;
            exp_len = priv.publicExponent_len;
        } else {
            exp_str = priv.privateExponent;
            exp_len = priv.privateExponent_len;
        }
        mod_str = priv.modulus;
        mod_len = priv.modulus_len;
    }
    while (exp_len > 0 && *exp_str == 0)
        exp_str++, exp_len--;
    while (mod_len > 0 && *mod_str == 0)
        mod_str++, mod_len--;
    while (args->content_len > 0 && *args->content == 0)
        args->content++, args->content_len--;
    
    if (exp_len > 8 || mod_len > 8)
        throw("ft_ssl: rsautl: key too long (64bit max)\n");
    
    if (args->content_len > 8)
        throw("ft_ssl: rsautl: message too long (64bit max)\n");

    for (int i = 0; i < exp_len; i++)
        *exp = (*exp << 8) | (u_int8_t)exp_str[i];

    for (int i = 0;i < mod_len; i++)
        *mod = (*mod << 8) | (u_int8_t)mod_str[i];

    for (int i = 0; i < args->content_len; i++)
        *m = (*m << 8) | (u_int8_t)args->content[i];

    
    dbg("exp = %lu, mod = %lu, msg = %lu\n", *exp, *mod, *m);
}

void rsautl(int ac, char **av)  {
    int flags = 0;
    t_rsautl_args args = INIT_RSAUTL_ARGS;
    args = parse_rsautl(ac, av, &flags);

    if (!(flags & RSA_FLAG_IN)) {
        args.content = (char *)read_fd(0, &args.content_len);
        args.content_len--;
    }
    put_fd("content hex : \n", 2);
    put_hex_fd(args.content, args.content_len, 2);
    put_fd("\n", 2);

    u_int64_t exp = 0, mod = 0, m = 0;
    get_exp_mod_msg(&args, flags, &exp, &mod, &m);

    if (m == 0)
        throw("ft_ssl: rsautl: message is null\n");

    u_int64_t c = 0;
    c = powmod(m, exp, mod);

    for (int i = 0; i < 8; i++) {
        char tmp = (c >> ((8 - i - 1) * 8)) & 0xff;
        write(args.out_fd, &tmp, 1);
    }
    //while (c > 0) {
        //char tmp = c & 0xFF;
        //write(args.out_fd, &tmp, 1);
        //c >>= 8;
    //}
}