#!/bin/bash
echo ""
echo "************** TESTING RSA **************"
echo ""

mkdir -p bin
for i in {0..7}; do

    n=3

    #head -c $n /dev/urandom | base64 | cat > bin/input



    ./ft_ssl genrsa --out bin/priv_key.pem 2> /dev/null
    ./ft_ssl rsa -in bin/priv_key.pem -pubout -out bin/pub_key.pem 2> /dev/null

    echo -n "TEST $i DIFF : " 

    ./ft_ssl rsautl -in bin/input -out bin/output -inkey bin/priv_key.pem -encrypt  #2> /dev/null
    ./ft_ssl rsautl -in bin/output -out bin/output2 -inkey bin/priv_key.pem -decrypt # 2> /dev/null

    if cmp -s "bin/output2" "bin/input"; then
        echo "✅"
    else
        echo "❌"
    fi

done