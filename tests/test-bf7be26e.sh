if [ -z "$(which mcookie)" ] || [ -z "$(which ln)" ] || [ -z "$(which find)" ]; then
    exit 125;
fi

# A faked hard link whose backing files are gone -- removed along with
# the directory of the first name of its file, where they are kept when
# PROOT_L2S_DIR is not set -- couldn't be lstat(2)ed anymore: the stat
# handler of link2symlink failed the syscall when it couldn't follow the
# chain, with EPERM at that.  Besides, a chain that doesn't end at a
# file named with a count is not one link2symlink made, yet a count was
# parsed out of whatever name it ended at, and that file was deleted
# when this count dropped to 0.

DIR=${TMPDIR:?}/$(mcookie).l2s
mkdir -p "${DIR}/d1" "${DIR}/d2"

# A chain link2symlink did not make, and a file it did not name.
echo keep > "${DIR}/plain"
ln -s "${DIR}/plain" "${DIR}/.l2s.x0001"
ln -s "${DIR}/.l2s.x0001" "${DIR}/s"
echo name > "${DIR}/.l2s.y"

set +e
${PROOT} -l sh -c '
cd "$1" || exit 1
echo 1 > d1/a; ln d1/a d2/b
echo 2 > e; ln e f
' sh "${DIR}"
rm -rf "${DIR}/d1"

RESULT=$(${PROOT} -l sh -c '
cd "$1" || exit 1
[ -L d2/b ]; echo "lstat $?"
[ -e d2/b ]; echo "stat $?"
rm d2/b; echo "rm $? [$(ls -A d2)]"
echo "healthy $(find f -printf %n) $(cat f)"
echo "count $(find .l2s.y -printf %n)"
rm s; echo "plain $? $(cat plain)"
' sh "${DIR}" 2>&1)
STATUS=$?
set -e

rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='lstat 0
stat 1
rm 0 []
healthy 2 2
count 1
plain 0 keep'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
