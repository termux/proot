if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which find)" ] || [ -z "$(which xargs)" ]; then
    exit 125;
fi

# link2symlink tells apart the files of the same name it has moved --
# in the same directory, or anywhere in the guest rootfs when they are
# all kept in PROOT_L2S_DIR -- with a 4-digit suffix, but stopped at 999
# of them: the 1000th file of a name failed to be linked with EMLINK,
# or replaced the 999th before free suffixes were reserved.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/d" "${DIR}/l2s"

if ! gcc "${SCRIPT_DIR}/link.c" -o "${DIR}/link" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

# 999 other files named "a" are linked already, 3 times each.
echo 1 > "${DIR}/a"
I=1
while [ ${I} -le 999 ]; do
    printf '%s/.l2s.a%04d.0003\n' "${DIR}" ${I}
    I=$((I + 1))
done | xargs touch
I=1
while [ ${I} -le 999 ]; do
    ln -s "$(printf '%s/.l2s.a%04d.0003' "${DIR}" ${I})" "$(printf '%s/.l2s.a%04d' "${DIR}" ${I})"
    I=$((I + 1))
done

# The same, elsewhere in the guest rootfs, with an l2s directory: these
# are only told apart by the final files of their chains.
echo 2 > "${DIR}/d/a"
I=1
while [ ${I} -le 999 ]; do
    printf '%s/l2s/.l2s.a%04d.0002\n' "${DIR}" ${I}
    I=$((I + 1))
done | xargs touch

set +e
RESULT=$(${PROOT} -l sh -c '
cd "$1" || exit 1
./link a b; echo "next $? $(cat a)$(cat b) $(find a -printf %n)"
' sh "${DIR}" 2>&1
PROOT_L2S_DIR="${DIR}/l2s" ${PROOT} -l sh -c '
cd "$1" || exit 1
./link d/a d/b; echo "l2sdir $? $(cat d/a)$(cat d/b) $(find d/a -printf %n)"
' sh "${DIR}" 2>&1)
STATUS=$?
set -e

RESULT="${RESULT}
$(readlink "${DIR}/b" | sed "s|^${DIR}|D|") $(readlink "${DIR}/d/b" | sed "s|^${DIR}|D|")"

rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='next 0 11 2
l2sdir 0 22 2
D/.l2s.a1000 D/l2s/.l2s.a1000'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
