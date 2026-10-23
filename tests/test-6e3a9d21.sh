if [ -z "$(which mcookie)" ] || [ -z "$(which ln)" ] || [ -z "$(which stat)" ] || [ -z "$(which ls)" ] || ! ln --help 2>&1 | grep -q -- '-L'; then
    exit 125;
fi

# With AT_SYMLINK_FOLLOW, linkat(2) -- ln(1) on Termux, "ln -L" elsewhere
# -- got the file a faked hard link stands for: PRoot dereferenced the
# link like any symbolic link.  link2symlink then linked this file of its
# own as a new one, under a name made of its own name, and the count of
# the first chain stayed as it was.

DIR=${TMPDIR:?}/$(mcookie).l2s
mkdir "${DIR}"

set +e
RESULT=$(${PROOT} -l sh -c '
cd "$1" || exit 1
echo 1 > a
ln -L a b; echo "first $? $(stat -L -c %h a)"
ln -L b c; echo "faked $? $(stat -L -c %h a)"
rm a b; echo "rm $? $(cat c) $(stat -L -c %h c)"
' sh "${DIR}" 2>&1)
set -e

LEFT=$(ls -A "${DIR}" | grep -c '^\.l2s\..*\.l2s\.' || true)
rm -rf "${DIR}"

EXPECTED='first 0 2
faked 0 3
rm 0 1 1'

if [ "${RESULT}" != "${EXPECTED}" ] || [ "${LEFT}" -ne 0 ]; then
    echo "${RESULT}"
    echo "nested: ${LEFT}"
    exit 1
fi

exit 0
