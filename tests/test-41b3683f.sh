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
# Android's app policy raises SIGSYS on statx(2) before Android 11, and
# PRoot emulates it then.  The syscall being emulated has to be the one
# the mode is chosen for, not the one made before: with a chmod(2) there,
# the file statx(2) looked at was given the mode chmod(2) had set.
#
# The helpers exit with 125 on kernels without the syscall, and in "trap"
# mode where there's no seccomp filter.

NAME=$(mcookie)
HOST=${ROOTFS}/tmp/${NAME}
GUEST=/tmp/${NAME}

trap 'chmod -R u+rwx "${HOST}" 2>/dev/null; rm -rf "${HOST}"' EXIT

mkdir "${HOST}" "${HOST}/dir" "${HOST}/closed"
touch "${HOST}/file" "${HOST}/none" "${HOST}/other" "${HOST}/closed/file"
ln -s file "${HOST}/link"
chmod 440 "${HOST}/file"
chmod 000 "${HOST}/none"
chmod 555 "${HOST}/dir"
chmod 640 "${HOST}/closed/file"
chmod 000 "${HOST}/closed"

check() {
    CMD="$1 ${PROOT} -r ${ROOTFS} /bin/${HELPER}"
    CMD0="$1 ${PROOT} -0 -r ${ROOTFS} /bin/${HELPER}"

    CTIME=$(stat -c %z "${HOST}/file")

    # The mode of the last component is the actual one.
    [ "$(${CMD0} "${GUEST}/file")" = "440" ]
    [ "$(${CMD0} "${GUEST}/none")" = "0" ]
    [ "$(${CMD0} "${GUEST}/dir")" = "555" ]

    # AT_SYMLINK_NOFOLLOW looks at the link, the file it points to is left
    # alone.
    [ "$(${CMD0} -n "${GUEST}/link")" = "777" ]

    # Whatever the syscall made before.
    [ "$(${CMD0} -c "${GUEST}/other" "${GUEST}/file")" = "440" ]

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

    TRAP="${ROOTFS}/bin/${HELPER} trap"

    STATUS=0
    ${PROOT} -0 -r ${ROOTFS} /bin/${HELPER} "${GUEST}/file" > /dev/null || STATUS=$?
    if [ ${STATUS} -eq 125 ]; then
        exit 125
    fi

    check ""

    # Unless there's no seccomp filter (125), or what runs PRoot can't run
    # under this one (159, SIGSYS): valgrind calls statx(2) too.
    STATUS=0
    ${TRAP} ${PROOT} -0 -r ${ROOTFS} /bin/${HELPER} "${GUEST}/file" > /dev/null 2>&1 || STATUS=$?
    if [ ${STATUS} -ne 125 ] && [ ${STATUS} -ne 159 ]; then
        check "${TRAP}"
    fi
done

exit 0
