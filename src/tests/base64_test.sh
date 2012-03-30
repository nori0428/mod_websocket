#!/bin/bash
# https://github.com/ncb000gt/node-base64/tree/master/tests

set -e

FILES=$(find *.{png,txt} -type f)

for file in $FILES; do
    perlf=${file}-perl-out
    cf=${file}-c-out

    echo "check: $file"

    perl base64.pl $file > $perlf
    ./base64_encode_test $file > $cf

    cmp $perlf $cf

    rm -rf $perlf $cf
    ./base64_decode_test $file
done

# EOF

