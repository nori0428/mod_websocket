#!/bin/sh

LIGHTTPD_VERSION=`cat ./contrib/lighttpd1.4/configure.ac | grep AC_INIT | sed -e 's/[^\[]*\[\([^]]*\)\][^\[]*\[\([^]]*\)\].*/\1-\2/'`
if [ -z ${LIGHTTPD_VERSION} ]; then
    echo "no version"
    exit 1
fi
echo "Target Lighttpd version: ${LIGHTTPD_VERSION}"

if [ -f ./patches/${LIGHTTPD_VERSION}/websocket.patch ]; then
    echo "already exists"
    exit 1
fi

# make patch
mkdir -p ./patches/${LIGHTTPD_VERSION}
mkdir -p ./workspace
rm -fr ./workspace/*
cp -r ./contrib/lighttpd1.4 ./workspace/lighttpd1.4.orig
cp -r ./contrib/lighttpd1.4 ./workspace/lighttpd1.4.patched

patch -N -d ./workspace/lighttpd1.4.patched -p1 < ./patches/base/websocket.patch
(cd ./workspace; diff -ur lighttpd1.4.orig lighttpd1.4.patched > ../patches/${LIGHTTPD_VERSION}/websocket.patch)

echo "done"
