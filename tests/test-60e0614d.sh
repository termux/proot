if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which find)" ] || [ -z "$(which xargs)" ]; then
    exit 125;
fi

# link2symlink told a free intermediate with access(2), which follows a
# dangling one -- that of a broken chain -- so the file was moved to the
# final name next to it, then left without any name at all when the
# intermediate could not be created.  The same went for a final file a
# broken chain left behind, which was replaced, and for the file linked
# once there were no free intermediates left, which replaced the last
# one's.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/l2s"

if ! gcc "${SCRIPT_DIR}/link.c" -o "${DIR}/link" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

# A dangling intermediate.
echo data > "${DIR}/a"
ln -s nowhere "${DIR}/.l2s.a0001"

# The final file of a chain whose intermediate is gone.
echo new > "${DIR}/c"
echo old > "${DIR}/.l2s.c0001.0002"

# No free intermediate left: 0001 to 0999 are taken by intermediates,
# 1000 to 9999 by the final files of broken chains.
echo mine > "${DIR}/e"
I=1
while [ ${I} -le 999 ]; do
    ln -s "${DIR}/.l2s.e0999.0002" "${DIR}/$(printf .l2s.e%04d ${I})"
    I=$((I + 1))
done
echo other > "${DIR}/.l2s.e0999.0002"
while [ ${I} -le 9999 ]; do
    printf '%s/.l2s.e%04d.0002\n' "${DIR}" ${I}
    I=$((I + 1))
done | xargs touch

# A dangling intermediate in the l2s directory.
echo 7 > "${DIR}/g"
ln -s nowhere "${DIR}/l2s/.l2s.g0001"

set +e
RESULT=$(${PROOT} -l sh -c '
cd "$1" || exit 1
./link a b; echo "dangling $? $(cat a)$(cat b) $(find a -printf %n)"
./link c d; echo "stale $? $(cat c)$(cat d) $(find c -printf %n)"
./link e f; echo "full $? $(cat e) $([ -e f ] || [ -L f ]; echo $?)"
' sh "${DIR}" 2>&1
PROOT_L2S_DIR="${DIR}/l2s" ${PROOT} -l sh -c '
cd "$1" || exit 1
./link g h; echo "l2sdir $? $(cat g)$(cat h) $(find g -printf %n)"
' sh "${DIR}" 2>&1)
STATUS=$?
set -e

RESULT="${RESULT}
$(readlink "${DIR}/.l2s.a0001") $(cat "${DIR}/.l2s.c0001.0002") $(cat "${DIR}/.l2s.e0999.0002") $(readlink "${DIR}/l2s/.l2s.g0001")"

rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='dangling 0 datadata 2
stale 0 newnew 2
full 31 mine 1
l2sdir 0 77 2
nowhere old other nowhere'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
