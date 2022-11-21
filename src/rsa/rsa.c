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
            args->in_fd = open(av[i], O_RDONLY);
            if (args->in_fd < 0)
                throw(cat("ft_ssl: rsa: ", av[i], ": No such file or directory\n"));
            args->content = (char *)read_fd(args->in_fd, &args->content_len);
        } else if (!ft_strcmp("-passin", av[i])) {
            if (i == ac - 1)
                throw(cat("ft_ssl: rsa: option ", av[i], " requires an argument\n"));
            i++;
            *flags |= RSA_FLAG_PASSIN;
            //...
        } else if (!ft_strcmp("-out", av[i])) {
            if (i == ac - 1)
                throw(cat("ft_ssl: rsa: option ", av[i], " requires an argument\n"));
            i++;
            *flags |= RSA_FLAG_OUT;
            args->in_fd = open(av[i], O_RDONLY);
        } else if (!ft_strcmp("-passout", av[i])) {
            if (i == ac - 1)
                throw(cat("ft_ssl: rsa: option ", av[i], " requires an argument\n"));
            i++;
            *flags |= RSA_FLAG_PASSOUT;
            
        } else if (!ft_strcmp("-des", av[i])) {
            *flags |= RSA_FLAG_DES;
            
        } else if (!ft_strcmp("-text", av[i])) {
            *flags |= RSA_FLAG_TEXT;
            
        } else if (!ft_strcmp("-noout", av[i])) {
            *flags |= RSA_FLAG_NOOUT;
            
        } else if (!ft_strcmp("-modulus", av[i])) {
            *flags |= RSA_FLAG_MODULUS;
            
        } else if (!ft_strcmp("-check", av[i])) {
            *flags |= RSA_FLAG_CHECK;
            
        } else if (!ft_strcmp("-pubin", av[i])) {
            *flags |= RSA_FLAG_PUBIN;
            
        } else if (!ft_strcmp("-pubout", av[i])) {
            *flags |= RSA_FLAG_PUBOUT;
            
        } else {
            throw(cat("ft_ssl: rsa: invalid option -- '", av[i], "'\n"));
        }
    }
}

void rsa(int ac, char **av) {
    t_rsa_args args = INIT_RSA_ARGS;
    int flags = 0;
    parse_rsa(ac, av, &args, &flags);
    if (!(flags & RSA_FLAG_IN))
        args.content = (char *)read_fd(0, &args.content_len);

    // if private to pub -> parse + convert
    // else parse to check error into reprint input
    
    // key is private
    if (!(flags & RSA_FLAG_PUBIN)) {
        t_rsa_private_asn1 key = parse_private_key(&args);

        if (flags & RSA_FLAG_PUBOUT) {

            // need key in PEM format

            char *b64 = encrypt_base64((char *)key.modulus, key.modulus_len, NULL);
            put_fd("public key : \n", args.out_fd);
            put_fd(b64,  args.out_fd);
        }
    } else {
        t_rsa_public_asn1 key = parse_public_key(&args);
        (void)key;
    }

    
    

}