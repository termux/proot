if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which find)" ]; then
    exit 125;
fi

# link2symlink records the link count of a file in its name, with 4
# digits up to 9999 links and 5 from 10000 on, but read it back as its
# last 4 characters.  The 10000th link therefore left a chain that
# looked broken: 1 link, ENOENT for the next link(2), no count
# decremented by unlink(2), the name of the file in the l2s directory
# reported in /proc/self/fd -- and a count of 0, that is, the file
# deleted at the first unlink(2), before broken chains were left alone.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}"

if ! gcc "${SCRIPT_DIR}/link.c" -o "${DIR}/link" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

# Set the link count of the file "a" to $1, as many links would have.
set_count() {
    FINAL=$(readlink "${DIR}/.l2s.a0001")
    mv "${FINAL}" "${FINAL%.*}.$1"
    rm "${DIR}/.l2s.a0001"
    ln -s "${FINAL%.*}.$1" "${DIR}/.l2s.a0001"
}

echo data > "${DIR}/a"

set +e
${PROOT} -l "${DIR}/link" "${DIR}/a" "${DIR}/b" && set_count 9999
RESULT=$(${PROOT} -l sh -c '
cd "$1" || exit 1
./link a c; echo "up $? $(find a -printf %n) $(stat -c %h c)"
exec 3< c; echo "fd $(readlink /proc/self/fd/3 | sed "s|.*/||")"; exec 3<&-
./link a d; echo "next $? $(find a -printf %n)"
rm c d; echo "down $? $(find a -printf %n) $(cat a)"
' sh "${DIR}" 2>&1)
STATUS=$?

RESULT="${RESULT}
$(ls -A "${DIR}" | grep '^\.l2s\.a0001\.')"

set_count 999999999
RESULT="${RESULT}
$(${PROOT} -l sh -c '
cd "$1" || exit 1
./link a e; echo "max $? $(find a -printf %n) $(cat a)"
' sh "${DIR}" 2>&1)"
set -e

rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='up 0 10000 10000
fd c
next 0 10001
down 0 9999 data
.l2s.a0001.9999
max 31 999999999 data'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
