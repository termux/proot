if [ -z "$(which mcookie)" ] || [ ! -x ${ROOTFS}/bin/fd_reuse ]; then
    exit 125;
fi

# PRoot remembers the guest path a descriptor was opened through with
# O_PATH (see remember_fd_path()): "/x" and "/y" below lead to the same
# host directory, which is all the kernel reports, but what is below them
# differs.  close(2) doesn't stop the tracees anymore, so such an entry
# outlives its descriptor, and has to be dropped before the number gets
# reused: here "sub/which" relative to the descriptor of "/y" was looked
# up below "/x".

DIR=${TMPDIR:?}/$(mcookie)
mkdir -p "${DIR}/A/sub" "${DIR}/B"
echo A > "${DIR}/A/sub/which"
echo B > "${DIR}/B/which"

set +e
RESULT=$(${PROOT} -b /proc -r ${ROOTFS} -b "${DIR}/A:/y" -b "${DIR}/A:/x" -b "${DIR}/B:/y/sub" \
                  /bin/fd_reuse /x /y sub/which)
STATUS=$?
set -e

rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

if [ "${RESULT}" != "B" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
