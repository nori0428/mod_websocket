#!/bin/sh
# for Travis CI

# --with-libicu
./configure --with-test
make clean check

# --without-libicu
./configure --without-libicu --with-test
make clean check

# --with-openssl --with-libicu
./configure --with-openssl --with-test
make clean check

# --with-openssl --without-libicu
./configure --without-libicu --with-openssl --with-test
make clean check
