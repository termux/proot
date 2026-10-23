if [ -z "$(which mcookie)" ] || [ -z "$(which stat)" ] || [ -z "$(which id)" ] || [ ! -x ${ROOTFS}/bin/statx ]; then
    exit 125;
fi

if [ "$(id -u)" -eq 0 ]; then
    exit 125;
fi

# With -0 the permissions of every path component are forced to rwx
# during the translation, to emulate CAP_DAC_OVERRIDE, and restored
# afterwards.  The stat syscalls have to see the actual mode of the last
# component, so it is left alone for them, statx(2) included: "ls -l" and
# "stat" from coreutils use it, as does stat(3) of 32-bit glibc programs.
# Forcing the mode also changed the ctime of the file at each look.
#
# The helpers exit with 125 on kernels without the syscall.

NAME=$(mcookie)
HOST=${ROOTFS}/tmp/${NAME}
GUEST=/tmp/${NAME}

trap 'chmod -R u+rwx "${HOST}" 2>/dev/null; rm -rf "${HOST}"' EXIT

mkdir "${HOST}" "${HOST}/dir" "${HOST}/closed"
touch "${HOST}/file" "${HOST}/none" "${HOST}/closed/file"
ln -s file "${HOST}/link"
chmod 440 "${HOST}/file"
chmod 000 "${HOST}/none"
chmod 555 "${HOST}/dir"
chmod 640 "${HOST}/closed/file"
chmod 000 "${HOST}/closed"

check() {
    CMD="${PROOT} -r ${ROOTFS} /bin/${HELPER}"
    CMD0="${PROOT} -0 -r ${ROOTFS} /bin/${HELPER}"

    CTIME=$(stat -c %z "${HOST}/file")

    # The mode of the last component is the actual one.
    [ "$(${CMD0} "${GUEST}/file")" = "440" ]
    [ "$(${CMD0} "${GUEST}/none")" = "0" ]
    [ "$(${CMD0} "${GUEST}/dir")" = "555" ]

    # AT_SYMLINK_NOFOLLOW looks at the link, the file it points to is left
    # alone.
    [ "$(${CMD0} -n "${GUEST}/link")" = "777" ]

    [ "$(stat -c %z "${HOST}/file")" = "${CTIME}" ]
    [ "$(stat -c %a "${HOST}/file")" = "440" ]

    # The permissions of the other components are still overridden, and
    # restored afterwards.
    [ "$(${CMD} "${GUEST}/closed/file")" = "EACCES" ]
    [ "$(${CMD0} "${GUEST}/closed/file")" = "640" ]
    [ "$(stat -c %a "${HOST}/closed")" = "0" ]
}

for HELPER in statx statx-m32; do
    if [ ! -x ${ROOTFS}/bin/${HELPER} ]; then
        continue
    fi

    STATUS=0
    ${PROOT} -0 -r ${ROOTFS} /bin/${HELPER} "${GUEST}/file" > /dev/null || STATUS=$?
    if [ ${STATUS} -eq 125 ]; then
        exit 125
    fi

    check
done

exit 0
