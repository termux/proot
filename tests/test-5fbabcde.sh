if [ -z "$(which mcookie)" ] || [ ! -x ${ROOTFS}/bin/statx ]; then
    exit 125;
fi

# Where the kernel doesn't have statx(2), PRoot emulates it with
# [l]stat(2) at the exit stage.  It did so whatever the error, though:
# the EINVAL of a reserved mask bit became a made-up success, and the
# path of each file that doesn't exist was translated a second time,
# only to get ENOENT again.

set +e
${ROOTFS}/bin/statx -m 0x80000000 / > /dev/null
STATUS=$?
set -e
if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

for OPTIONS in "" "-0" "-l" "-0 -l"; do
    set +e
    RESULT=$(${PROOT} ${OPTIONS} -b /proc -r ${ROOTFS} /bin/statx -m 0x80000000 /)
    set -e
    if [ "${RESULT}" != "EINVAL" ]; then
        echo "[${OPTIONS}] reserved mask bit: ${RESULT}"
        exit 1
    fi

    set +e
    RESULT=$(${PROOT} ${OPTIONS} -b /proc -r ${ROOTFS} /bin/statx /$(mcookie))
    set -e
    if [ "${RESULT}" != "ENOENT" ]; then
        echo "[${OPTIONS}] missing file: ${RESULT}"
        exit 1
    fi

    RESULT=$(${PROOT} ${OPTIONS} -b /proc -r ${ROOTFS} /bin/statx /bin/statx)
    if [ "${RESULT}" != "$(${ROOTFS}/bin/statx ${ROOTFS}/bin/statx)" ]; then
        echo "[${OPTIONS}] existing file: ${RESULT}"
        exit 1
    fi
done

exit 0
