for i in {1..7}; do

    key=$(($RANDOM))
    n=$(($RANDOM))
    iv=$(($RANDOM))
    head -c $n /dev/urandom > bin/input

    echo ""
    echo "TEST $i [input size: $n key: $key iv: $iv]"
    echo ""

    openssl des-ecb -K $key -in bin/input -out bin/openssl_output 2> /dev/null
    ./ft_ssl des-ecb -k $key -i bin/input -o bin/ft_output

    echo -n "DES-ECB: "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅"
    else
        echo -n "Encode: ❌"
        break;
    fi
    openssl des-ecb -K $key -in bin/openssl_output -d -out bin/openssl_output_dec 2> /dev/null
    ./ft_ssl des-ecb -k $key -i bin/ft_output -d -o bin/ft_output_dec

    if cmp -s "bin/openssl_output_dec" "bin/ft_output_dec"; then
        echo " Decode: ✅"
    else
        echo " Decode: ❌"
        break;
    fi

    echo "";
    openssl des-cbc -K $key -in bin/input -out bin/openssl_output -iv $iv 2> /dev/null
    ./ft_ssl des-cbc -k $key -i bin/input -o bin/ft_output -v $iv


    echo -n "DES-CBC: "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅"
    else
        echo -n "Encode: ❌"
        break;
    fi
    openssl des-cbc -K $key -in bin/openssl_output -d -out bin/openssl_output_dec -iv $iv 2> /dev/null 
    ./ft_ssl des-cbc -k $key -i bin/ft_output -d -o bin/ft_output_dec -v $iv

    if cmp -s "bin/openssl_output_dec" "bin/ft_output_dec"; then
        echo " Decode: ✅"
    else
        echo " Decode: ❌"
        break;
    fi
    echo ""

done