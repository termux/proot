if [ -z "$(which mcookie)" ] || [ -z "$(which ln)" ] || [ -z "$(which stat)" ] || [ -z "$(which gcc)" ]; then
    exit 125;
fi

# link2symlink used to decrement the link count of the name rename(2)
# replaces -- or unlink(2) removes -- before the kernel did it, whatever
# the outcome: a failed call left the count one too low, so the data
# were deleted along with the next-to-last name, or right away if it was
# the last one.  Besides, two faked hard links of the same file are two
# symbolic links to the kernel, so renaming one onto the other removed
# the former instead of doing nothing (#419).

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir "${DIR}"

if ! gcc "${SCRIPT_DIR}/renameat2.c" -o "${DIR}/renameat2" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

# Not every filesystem supports RENAME_EXCHANGE, ecryptfs for instance.
touch "${DIR}/p" "${DIR}/q"
if ! "${DIR}/renameat2" "${DIR}/p" "${DIR}/q" 2; then
    rm -rf "${DIR}"
    exit 125
fi
rm "${DIR}/p" "${DIR}/q"

set +e
RESULT=$(${PROOT} -l sh -c '
cd "$1" || exit 1

# Both names of the same file: nothing to do, unless RENAME_NOREPLACE.
echo 1 > a; ln a b
./renameat2 a b 0; echo "same $? $(cat a)$(cat b) $(stat -L -c %h a)"
./renameat2 a b 1; echo "noreplace $? $(stat -L -c %h a)"
./renameat2 a b 2; echo "exchange $? $(stat -L -c %h a)"
./renameat2 a a 0; echo "self $? $(stat -L -c %h a)"

# The last name onto itself.
rm b; ./renameat2 a a 0; echo "last $? $(cat a)"

# A failed rename(2) or unlink(2) has removed nothing.
ln a b; ./renameat2 missing b 0; echo "missing $? $(stat -L -c %h a)"
rm a; echo "next $(cat b)"
mkdir dir; ./renameat2 dir b 0; echo "dir $? $(cat b)"
ln b c; mkdir ro; mv c ro/c; chmod 555 ro
if [ "$(id -u)" -ne 0 ]; then
    rm -f ro/c 2>/dev/null; echo "ro $? $(stat -L -c %h b)"
else
    echo "ro 1 2"
fi
chmod 755 ro

# RENAME_EXCHANGE gives each name the file of the other.
echo 2 > d; ./renameat2 d b 2; echo "swap $? $(cat b)$(cat d) $(stat -L -c %h d)"

# Replacing a name of another file does decrement its count.
./renameat2 b d 0; echo "replace $? $(cat d) $(stat -L -c %h ro/c)"
' sh "${DIR}" 2>&1)
STATUS=$?
set -e

rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='same 0 11 2
noreplace 1 2
exchange 0 2
self 0 2
last 0 1
missing 1 2
next 1
dir 1 1
ro 1 2
swap 0 21 2
replace 0 2 1'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
