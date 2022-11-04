#for i in {0..7}; do
i=0
while true; do

    n=$(($RANDOM))
    n=$((n * i))

    head -c $n /dev/urandom > bin/input

    echo "TEST $i [input size: $n]"

    openssl base64 -in bin/input -out bin/openssl_output 2> /dev/null
    ./ft_ssl base64 -i bin/input -o bin/ft_output #2> /dev/null

    if cmp -s "bin/openssl_output" "bin/ft_output"; then
        echo  "Encode: ✅"
    else
        echo  "Encode: ❌"
        break;
    fi
    openssl base64 -in bin/openssl_output -out bin/openssl_output_dec -d #2> /dev/null
    ./ft_ssl base64 -i bin/ft_output -o bin/ft_output_dec -d #2> /dev/null

    if cmp -s "bin/openssl_output_dec" "bin/ft_output_dec"; then
        echo " Decode: ✅"
    else
        echo " Decode: ❌"
        break;
    fi

    i=$((i + 1))
done