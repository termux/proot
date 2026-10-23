if [ ! -x  ${ROOTFS}/bin/true ] || [ -z `which mcookie` ] || [ -z `which true` ] || [ -z `which mkdir` ] || [ -z `which ln` ] || [ -z `which rm` ]; then
    exit 125;
fi

TMP=/tmp/$(mcookie)

A=$(mcookie)
B=$(mcookie)

# Relative symlinks with a ".." for each component of their directory on
# the host, so they climb out of the rootfs there, while in the guest
# they stop at its root.  "ln -r" can't make them: it climbs only up to
# the prefix shared with the target, and resolves symlinks in the target,
# /bin/true to /usr/bin/true where /bin is one.
UP=$(echo ${ROOTFS}/${TMP} | tr -s / | sed 's|/[^/]*|../|g')

mkdir -p ${ROOTFS}/${TMP}

ln -s ${UP}bin/true ${ROOTFS}/${TMP}/${A}
ln -s ${UP}${TMP#/}/${A} ${ROOTFS}/${TMP}/${B}

if [ ! -e ${ROOTFS}/${TMP}/${A} ]; then
    exit 125;
fi

env PATH=${TMP} ${PROOT} -r ${ROOTFS} ${B}

rm -f ${TMP}/${B}  # just in case it also exists in the host env.
${PROOT} -r ${ROOTFS} /${TMP}/${B}

rm -fr ${ROOTFS}/${TMP}
