if [ ! -x  ${ROOTFS}/bin/readlink ] || [ -z `which mcookie` ] || [ -z `which touch` ] || [ -z `which mkdir` ] || [ -z `which ln` ] || [ -z `which grep` ] || [ -z `which rm` ]; then
    exit 125;
fi

HOST=${TMPDIR:?}
REGULAR=`mcookie`
SYMLINK=`mcookie`

touch ${HOST}/${REGULAR}
ln -fs ${HOST}/${REGULAR} ${HOST}/${SYMLINK}

# Same content in the rootfs, where it is a guest path.
mkdir -p ${ROOTFS}/tmp
ln -fs ${HOST}/${REGULAR} ${ROOTFS}/tmp/${SYMLINK}

${PROOT} -b ${HOST}:/ced -r ${ROOTFS} /bin/readlink /tmp/${SYMLINK} | grep ^${HOST}/${REGULAR}$
${PROOT} -b ${HOST}:/ced -r ${ROOTFS} /bin/readlink /ced/${SYMLINK} | grep ^/ced/${REGULAR}$

rm -f ${HOST}/${REGULAR}
rm -f ${HOST}/${SYMLINK}
rm -f ${ROOTFS}/tmp/${SYMLINK}
