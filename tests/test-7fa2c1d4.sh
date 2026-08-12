if [ -z "$(which mcookie)" ] || [ -z "$(which readlink)" ] || [ -z "$(which ln)" ]; then
    exit 125;
fi

# A hard link faked by link2symlink must not be named after the file it
# is stored as in the l2s directory.  The path hiding is done on the
# arguments of syscalls, but the kernel knows the file it gave a
# descriptor on by its real name and reports it in "/proc/<PID>/fd/<FD>";
# programs resolving a path the fast way -- open(O_PATH) then readlink()
# on that link, as typescript-go and musl's realpath(3) do -- got
# "/.l2s/.l2s.<name>0001.0002" instead of the name they opened.

DIR=/tmp/$(mcookie).l2s
mkdir "${DIR}"
echo content > "${DIR}/original"

RESULT=$(${PROOT} -l -b /proc sh -c "ln ${DIR}/original ${DIR}/link && exec 3< ${DIR}/link && readlink /proc/self/fd/3")

rm -rf "${DIR}"

if [ "${RESULT}" != "${DIR}/link" ]; then
    exit 1
fi

exit 0
