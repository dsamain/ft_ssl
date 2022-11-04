for i in {0..12}; do

    key=$(($RANDOM))
    n=$(($RANDOM))
    iv=$(($RANDOM))
    pass=$(($RANDOM))

    n=$((n * i))

    head -c $n /dev/urandom > bin/input

    echo ""
    echo "TEST $i [input size: $n key: $key iv: $iv pass $pass]"
    echo ""

    # ___ DES_ECB ___

    openssl des-ecb -K $key -in bin/input -out bin/openssl_output 2> /dev/null
    ./ft_ssl des-ecb -k $key -i bin/input -o bin/ft_output

    echo -n " DES-ECB: "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅ |"
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

    openssl des-ecb -K $key -in bin/input -out bin/openssl_output -a 2> /dev/null
    ./ft_ssl des-ecb -k $key -i bin/input -o bin/ft_output -a

    echo -n " DES-ECB: "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅ |"
    else
        echo -n "Encode: ❌"
        break;
    fi
    openssl des-ecb -K $key -in bin/openssl_output -d -out bin/openssl_output_dec -a 2> /dev/null
    ./ft_ssl des-ecb -k $key -i bin/ft_output -d -o bin/ft_output_dec -a

    if cmp -s "bin/openssl_output_dec" "bin/ft_output_dec"; then
        echo " Decode: ✅"
    else
        echo " Decode: ❌"
        break;
    fi


    # ___ DES_CBC ___

    ./ft_ssl des-ecb -p $pass -i bin/input -o bin/ft_output
    ./ft_ssl des-ecb -p $pass -i bin/ft_output -o bin/ft_output_dec -d

    echo -n " DES-ECB with password: "
    if cmp -s "bin/ft_output_dec" "bin/input"; then
        echo "✅"
    else
        echo "❌"
        break;
    fi

    openssl des-cbc -K $key -in bin/input -out bin/openssl_output -iv $iv 2> /dev/null
    ./ft_ssl des-cbc -k $key -i bin/input -o bin/ft_output -v $iv

    echo ""

    echo -n " DES-CBC: "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅ |"
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

    ./ft_ssl des-cbc -p $pass -i bin/input -o bin/ft_output -v $iv
    ./ft_ssl des-cbc -p $pass -i bin/ft_output -o bin/ft_output_dec -d -v $iv

    echo -n " DES-CCB with password: "
    if cmp -s "bin/ft_output_dec" "bin/input"; then
        echo "✅"
    else
        echo "❌"
        break;
    fi

done