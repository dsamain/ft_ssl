while true ; do
    head -c 12 /dev/urandom | base64 > bin/in

    openssl base64 -in bin/in -out bin/o_out
    ./ft_ssl base64 -i bin/in -o bin/out

    if cmp -s "bin/o_out" "bin/out"; then
        echo "base64 encode : OK"
    else
        echo "base64 encode : KO"
        break;
    fi

    openssl base64 -in bin/o_out -out bin/o_out_dec -d
    ./ft_ssl base64 -i bin/out -o bin/out_dec -d

    if cmp -s "bin/o_out" "bin/out"; then
        echo "base64 decode : OK"
    else
        echo "base64 decode : KO"
        break;
    fi

done