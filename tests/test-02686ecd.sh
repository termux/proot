if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ]; then
    exit 125;
fi

# A path that doesn't exist in the guest rootfs can't be translated, so
# the syscall is discarded with that error.  link2symlink still handled
# link(2) though, with the path the tracee gave as is, that is, a path
# of the host: a file out of the guest rootfs was moved and replaced
# with a faked hard link.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/rootfs" "${DIR}/host"
echo content > "${DIR}/host/file"

if ! gcc -static "${SCRIPT_DIR}/link.c" -o "${DIR}/rootfs/link" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

set +e
${PROOT} -l -w / -r "${DIR}/rootfs" /link "${DIR}/host/file" /new
STATUS=$?
set -e

RESULT=$(ls -A "${DIR}/host")
TYPE=regular
if [ -L "${DIR}/host/file" ] || [ ! -f "${DIR}/host/file" ]; then
    TYPE=other
fi

rm -rf "${DIR}"

if [ ${STATUS} -eq 0 ] || [ "${RESULT}" != "file" ] || [ "${TYPE}" != regular ]; then
    echo "${STATUS} ${RESULT} ${TYPE}"
    exit 1
fi

exit 0
