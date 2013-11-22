#!/bin/sh
# for Travis CI

# only hybi-00
./configure --with-websocket=ietf-00
make clean check

# only rfc-6455
./configure --with-websocket=rfc-6455
make clean check

# both
./configure
make clean check
