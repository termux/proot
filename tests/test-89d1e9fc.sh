if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which stat)" ] || [ -z "$(which cat)" ]; then
    exit 125;
fi

# link2symlink records the link count of a file in the name of its final
# file, "<intermediate>.<count>", and renames it as this count changes.
# rename(2) replaced whatever had the new name: what a broken chain left
# behind -- a new chain only checks the name it gets for 2 links -- or a
# file its tracee named like that.  That file was lost.  The count is
# left as it is now when its name is taken: the file can't get one more
# link, and a count too high only keeps it longer.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}"

if ! gcc "${SCRIPT_DIR}/link.c" -o "${DIR}/link" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

cd "${DIR}"

# In the way of the third link of "a".
echo kept > .l2s.a0001.0003
echo a > a

# In the way of the count of "x" once "z" is removed.
echo x > x

set +e
RESULT=$(
${PROOT} -l sh -c '
./link a b; echo "two $? $(stat -c %h a)"
./link a c; echo "three $? $(stat -c %h a) $(cat .l2s.a0001.0003)"
./link x y; ./link x z; echo "x $? $(stat -c %h x)"
' 2>&1
echo kept > .l2s.x0001.0002
${PROOT} -l sh -c '
rm z; echo "rm $? $(stat -c %h x) $(cat .l2s.x0001.0002)"
rm y; echo "rm $? $(stat -c %h x) $(cat x)"
' 2>&1
)
STATUS=$?
set -e

cd /
rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='two 0 2
three 31 2 kept
x 0 3
rm 0 3 kept
rm 0 3 x'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
