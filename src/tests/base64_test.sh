#!/bin/bash
# https://github.com/ncb000gt/node-base64/tree/master/tests

set -e

FILES=$(find *.png -type f)

for file in $FILES; do
    perlf=${file}-perl-out
    cf=${file}-c-out

    echo "check: $file"

    perl base64.pl $file > $perlf
    ./base64_test $file > $cf

    cmp $perlf $cf

    rm -rf $perlf $cf
done

# EOF

