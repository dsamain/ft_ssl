for i in {0..12}; do

    key=$(($RANDOM))
    n=$(($RANDOM))
    iv=$(($RANDOM))
    pass=$(($RANDOM))
    salt=$(($RANDOM))

    n=$((n * i))

    head -c $n /dev/urandom > bin/input
    #echo "test" > bin/input

    echo ""
    echo "TEST $i [input size: $n key: $key iv: $iv pass $pass]"
    echo ""

    # ___ DES_ECB ___

    openssl des-ecb -K $key -in bin/input -out bin/openssl_output 2> /dev/null
    ./ft_ssl des-ecb -k $key -i bin/input -o bin/ft_output

    echo -n " DES-ECB (key)    : "
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

    openssl des-ecb -pass pass:$pass -S $salt -in bin/input -out bin/openssl_output -pbkdf2 2> /dev/null
    ./ft_ssl des-ecb -p $pass -s $salt -i bin/input -o bin/ft_output #2> /dev/null

    echo -n " DES-ECB (pass)   : "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅ | "
    else
        echo -n "Encode: ❌"
        break;
    fi

    openssl des-ecb -pass pass:$pass -S $salt -in bin/openssl_output -out bin/openssl_output_dec -pbkdf2 -d 2> /dev/null
    ./ft_ssl des-ecb -p $pass -s $salt -i bin/ft_output -o bin/ft_output_dec -d #2> /dev/null

    if cmp -s "bin/openssl_output_dec" "bin/ft_output_dec"; then
        echo "Decode: ✅"
    else
        echo "Decode: ❌"
        break;
    fi

    openssl des-ecb -K $key -in bin/input 2> /dev/null | base64 > bin/openssl_output 2> /dev/null
    ./ft_ssl des-ecb -k $key -i bin/input -o bin/ft_output -a

    echo -n " DES-ECB (base64) : "
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

    echo ""
    # ___ DES_CBC ___

    openssl des-cbc -iv $iv -K $key -in bin/input -out bin/openssl_output 2> /dev/null
    ./ft_ssl des-cbc -v $iv -k $key -i bin/input -o bin/ft_output

    echo -n " DES-CBC (key)    : "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅ |"
    else
        echo -n "Encode: ❌"
        break;
    fi
    openssl des-cbc -iv $iv -K $key -in bin/openssl_output -d -out bin/openssl_output_dec 2> /dev/null
    ./ft_ssl des-cbc -v $iv -k $key -i bin/ft_output -d -o bin/ft_output_dec

    if cmp -s "bin/openssl_output_dec" "bin/ft_output_dec"; then
        echo " Decode: ✅"
    else
        echo " Decode: ❌"
        break;
    fi

    openssl des-cbc -iv $iv -pass pass:$pass -S $salt -in bin/input -out bin/openssl_output -pbkdf2 2> /dev/null
    ./ft_ssl des-cbc -v $iv -p $pass -s $salt -i bin/input -o bin/ft_output #2> /dev/null

    echo -n " DES-CBC (pass)   : "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅ | "
    else
        echo -n "Encode: ❌"
        break;
    fi

    openssl des-cbc -iv $iv -pass pass:$pass -S $salt -in bin/openssl_output -out bin/openssl_output_dec -pbkdf2 -d 2> /dev/null
    ./ft_ssl des-cbc -v $iv -p $pass -s $salt -i bin/ft_output -o bin/ft_output_dec -d #2> /dev/null

    if cmp -s "bin/openssl_output_dec" "bin/ft_output_dec"; then
        echo "Decode: ✅"
    else
        echo "Decode: ❌"
        break;
    fi

    openssl des-cbc -iv $iv -K $key -in bin/input 2> /dev/null | base64 > bin/openssl_output  2> /dev/null
    ./ft_ssl des-cbc -v $iv -k $key -i bin/input -o bin/ft_output -a

    echo -n " DES-CBC (base64) : "
    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo -n "Encode: ✅ |"
    else
        echo -n "Encode: ❌"
        break;
    fi
    openssl des-cbc -iv $iv -K $key -in bin/openssl_output -d -out bin/openssl_output_dec -a 2> /dev/null
    ./ft_ssl des-cbc -v $iv -k $key -i bin/ft_output -d -o bin/ft_output_dec -a

    if cmp -s "bin/openssl_output_dec" "bin/ft_output_dec"; then
        echo " Decode: ✅"
    else
        echo " Decode: ❌"
        break;
    fi

done