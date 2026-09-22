if [ -z "$(which mcookie)" ] || [ -z "$(which ln)" ] || [ -z "$(which gcc)" ] || [ ! -x ${ROOTFS}/bin/puts_proc_self_exe ]; then
    exit 125;
fi

# Same as test-f3a8c2e1, but reach the executable with execveat(AT_FDCWD, ...).
# PRoot rewrites that syscall as execve internally; link2symlink still has to
# report the faked hard link the path leads to.

DIR=/tmp/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir "${DIR}" "${DIR}/bin" "${DIR}/lib"
cp ${ROOTFS}/bin/puts_proc_self_exe "${DIR}/lib/original"

if ! gcc "${SCRIPT_DIR}/execveat.c" -o "${DIR}/execveat" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

${PROOT} -l ln "${DIR}/lib/original" "${DIR}/lib/link"
ln -s ../lib/link "${DIR}/bin/symlink"

set +e
RESULT=$(${PROOT} -l -b /proc "${DIR}/execveat" "${DIR}/bin/symlink")
STATUS=$?
set -e

rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

if [ "${RESULT}" != "${DIR}/lib/link" ]; then
    exit 1
fi

exit 0
