#!/bin/sh

LIGHTTPD_DIR=$1
if [ ! -f ${LIGHTTPD_DIR}/configure.ac ]; then
    echo "not found: ${LIGHTTPD_DIR}/configure.ac"
    exit 1
fi

LIGHTTPD_VERSION=`cat ${LIGHTTPD_DIR}/configure.ac | grep AC_INIT | sed -e 's/[^\[]*\[\([^]]*\)\][^\[]*\[\([^]]*\)\].*/\1-\2/'`
if [ -z ${LIGHTTPD_VERSION} ]; then
    echo "invalid version"
    exit 1
fi

echo "Target Lighttpd version: ${LIGHTTPD_VERSION}"
while :
do
    echo "do patch? [y/n]"
    read ANS
    if [ ! -z ${ANS} ]; then
        break;
    fi
done

ANSWER=`echo ${ANS} | tr "[A-Z]" "[a-z]"`
if [ ${ANSWER} = 'y' -o ${ANSWER} = 'yes' ]; then
    if [ ! -d patches/${LIGHTTPD_VERSION} ]; then
        echo "patches for ${LIGHTTPD_VERSION} are not exist"
        exit 1
    fi
    PATCHES=`ls patches/${LIGHTTPD_VERSION}/*.patch`
    for p in ${PATCHES}
    do
        patch -d ${LIGHTTPD_DIR} -p1 < ${p}
    done
fi

# EOF
