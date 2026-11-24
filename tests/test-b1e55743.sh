if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ]; then
    exit 125;
fi

# link2symlink handed the -1 of the host syscalls its emulation of
# link(2) is made of -- rename(2), symlink(2), readlink(2), ... -- to
# the tracee as is, that is, as -EPERM, instead of their errno.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/l2s"

if ! gcc "${SCRIPT_DIR}/link.c" -o "${DIR}/link" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

set +e
RESULT=$(
${PROOT} -l sh -c '
cd "$1" || exit 1

# The new name exists.
echo 1 > a; echo 2 > b
./link a b; echo "exists $? $(cat a)"

./link a c
' sh "${DIR}" 2>&1

# The faked hard link is broken.  Its tracee can't remove the files of
# its chain, they are removed behind PRoot's back.
rm "${DIR}/.l2s.a0001" "${DIR}/.l2s.a0001.0002"

${PROOT} -l sh -c '
cd "$1" || exit 1
./link c d; echo "broken $?"

# The file can not be moved out of its directory.
mkdir ro; echo 3 > ro/e; chmod 555 ro
if [ "$(id -u)" -ne 0 ]; then
    ./link ro/e f; echo "ro $? $(cat ro/e)"
else
    echo "ro 13 3"
fi
chmod 755 ro
' sh "${DIR}" 2>&1

# The l2s directory was removed once in use -- behind PRoot's back
# again, its tracee can't remove it as long as it is not empty.
PROOT_L2S_DIR="${DIR}/l2s" ${PROOT} -l sh -c '
cd "$1" || exit 1
echo 4 > g; ./link g h; : > ready
i=0; while [ ! -e go ] && [ $i -lt 60 ]; do sleep 1; i=$((i + 1)); done
echo 5 > i; ./link i j; echo "gone $? $(cat i)"
' sh "${DIR}" > "${DIR}/gone" 2>&1 &
i=0; while [ ! -e "${DIR}/ready" ] && [ $i -lt 60 ]; do sleep 1; i=$((i + 1)); done
rm -rf "${DIR}/l2s"
: > "${DIR}/go"
wait $!
GONE=$?
cat "${DIR}/gone"
exit ${GONE}
)
STATUS=$?
set -e

chmod -R u+w "${DIR}"
rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='exists 17 1
broken 2
ro 13 3
gone 2 5'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
