#!/bin/sh

sample_dir=`pwd`/sample

# install mod_websocket to lighttpd
mkdir -p ./workspace
rm -fr ./workspace/lighttpd1.4
cp -r ./contrib/lighttpd1.4 ./workspace/
./bootstrap
./configure --with-lighttpd=./workspace/lighttpd1.4 --without-test
make clean all
echo y | make install

# create lighttpd.conf
INSTALL_ROOT_DIR=`echo ${sample_dir} | sed -e "s/\//\\\\\\\\\\//g"`
sed -e "s/_INSTALL_ROOT_DIR_/${INSTALL_ROOT_DIR}/" ./sample/etc/lighttpd.conf.in > ./sample/etc/lighttpd.conf

# install lighttpd to sample dir
(cd ./workspace/lighttpd1.4; \
 sh ./autogen.sh; \
 ./configure --with-websocket --prefix=${sample_dir}; \
  make clean install)
