if [ ! -x  ${ROOTFS}/bin/readlink ] || [ ! -x  ${ROOTFS}/bin/symlink ] || [ -z `which mcookie` ] || [ -z `which rm` ] || [ -z `which ln` ] || [ -z `which mkdir` ]; then
    exit 125;
fi

HOST=${TMPDIR:?}
LINK_NAME1=`mcookie`
LINK_NAME2=`mcookie`

rm -f ${HOST}/${LINK_NAME1}
rm -f ${HOST}/${LINK_NAME2}

mkdir -p ${ROOTFS}${HOST}

ln -s ${HOST}/ced-host ${HOST}/${LINK_NAME1}
ln -s ${HOST}/ced-guest ${ROOTFS}${HOST}/${LINK_NAME1}
${PROOT} -r ${ROOTFS} readlink ${HOST}/${LINK_NAME1} | grep ^${HOST}/ced-guest$
${PROOT} -b ${HOST} -r ${ROOTFS} readlink ${HOST}/${LINK_NAME1} | grep ^${HOST}/ced-host$
${PROOT} -b ${HOST}:/foo -r ${ROOTFS} readlink /foo/${LINK_NAME1} | grep ^/foo/ced-host$
${PROOT} -b ${HOST}:/foo -r ${ROOTFS} readlink ${HOST}/${LINK_NAME1} | grep ^${HOST}/ced-guest$

${PROOT} -b /:/host-rootfs -r ${ROOTFS} readlink ${HOST}/${LINK_NAME1} | grep ^${HOST}/ced-guest$
${PROOT} -b /:/host-rootfs -b ${HOST}:/foo -r ${ROOTFS} readlink ${HOST}/${LINK_NAME1} | grep ^${HOST}/ced-guest$

# Always use the deepest binding, deepest from the host point-of-view.
${PROOT} -b /:/host-rootfs -r ${ROOTFS} readlink ${HOST}/${LINK_NAME1} | grep ^${HOST}/ced-guest$
${PROOT} -b /:/host-rootfs -b ${HOST} -r ${ROOTFS} readlink ${HOST}/${LINK_NAME1} | grep ^${HOST}/ced-host$
${PROOT} -b /:/host-rootfs -b ${HOST}:/foo -r ${ROOTFS} readlink /foo/${LINK_NAME1} | grep ^/foo/ced-host$
${PROOT} -b /:/host-rootfs -b ${HOST} -r ${ROOTFS} readlink /host-rootfs${HOST}/${LINK_NAME1} | grep ^${HOST}/ced-host$
${PROOT} -b /:/host-rootfs -b ${HOST}:/foo -r ${ROOTFS} readlink /host-rootfs${HOST}/${LINK_NAME1} | grep ^/foo/ced-host$

rm ${HOST}/${LINK_NAME1}
rm ${ROOTFS}${HOST}/${LINK_NAME1}

${PROOT} -b /:/host-rootfs -b ${HOST} -w /bin -r ${ROOTFS} symlink /bin/bar /bin/${LINK_NAME1}
${PROOT} -b /:/host-rootfs -b ${HOST} -w /bin -r ${ROOTFS} readlink ${LINK_NAME1} | grep ^/bin/bar$
rm ${ROOTFS}/bin/${LINK_NAME1}

${PROOT} -b /:/host-rootfs -b ${HOST} -w ${HOST} -r ${ROOTFS} symlink /bin/bar ${HOST}/${LINK_NAME1}
${PROOT} -b /:/host-rootfs -b ${HOST} -w ${HOST} -r ${ROOTFS} readlink ${LINK_NAME1} | grep ^/bin/bar$
${PROOT} -b /:/host-rootfs -b ${HOST}:/foo -w /foo -r ${ROOTFS} symlink /foo/bar /foo/${LINK_NAME2}
${PROOT} -b /:/host-rootfs -b ${HOST}:/foo -w /foo -r ${ROOTFS} readlink ${LINK_NAME2} | grep ^/foo/bar$
${PROOT} -b /:/host-rootfs -b ${HOST} -w /host-rootfs${HOST} -r ${ROOTFS} readlink ${LINK_NAME2} | grep ^/foo/bar$
rm ${HOST}/${LINK_NAME2}
rm ${HOST}/${LINK_NAME1}
