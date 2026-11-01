if [ -z "$(which mcookie)" ] || [ -z "$(which readlink)" ] || [ -z "$(which ln)" ]; then
    exit 125;
fi

# link2symlink remembers the name a tracee used at open(2) time, keyed by
# the descriptor number open(2) returned.  Shells open a redirected file
# on a high descriptor then dup2(2) it onto the requested one, and other
# processes read "/proc/<PID>/fd/<FD>" under the final number, so the
# lookup used to miss and the real "/.l2s/.l2s.<name>0001.0002" path was
# reported instead of the name the file was opened through.

DIR=${TMPDIR:?}/$(mcookie).l2s
mkdir "${DIR}"
echo content > "${DIR}/original"

# Descriptor 9 was opened by the shell on another number, and is read by
# a child process.
RESULT=$(${PROOT} -l -b /proc sh -c "ln ${DIR}/original ${DIR}/link && exec 9< ${DIR}/link && sh -c 'readlink /proc/\$PPID/fd/9'")

# The redirection of a background process, read by its parent.
RESULT2=$(${PROOT} -l -b /proc sh -c "sleep 3 < ${DIR}/link & sleep 1; readlink /proc/\$!/fd/0; kill \$!")

rm -rf "${DIR}"

if [ "${RESULT}" != "${DIR}/link" ] || [ "${RESULT2}" != "${DIR}/link" ]; then
    exit 1
fi

exit 0
