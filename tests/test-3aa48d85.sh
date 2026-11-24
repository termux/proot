if [ -z "$(which mcookie)" ] || [ -z "$(which ln)" ] || [ -z "$(which mv)" ] || [ -z "$(which stat)" ] || [ -z "$(which cat)" ] || [ -z "$(which ls)" ]; then
    exit 125;
fi

# The names of a file link2symlink made hard links of record the host
# path of the intermediate of its chain, which records the one of its
# final file.  Unless PROOT_L2S_DIR is set, both are kept next to the
# first name of the file, so renaming a directory -- or one of its
# ancestors -- left every name in it dangling: the data was out of
# reach, and the chain was taken for a broken one.  These paths are
# updated now, when the names were moved along with their chain.  The
# names left elsewhere remain dangling.

export LC_ALL=C

DIR=${TMPDIR:?}/$(mcookie).l2s
mkdir -p "${DIR}"

SCENARIO='
cd "$1" || exit 1
mkdir -p d/sub o; echo one > d/a; ln d/a d/b; ln d/a d/sub/c; ln d/a o/out
mkdir -p t/debug/deps; echo two > t/debug/deps/f-1; ln t/debug/deps/f-1 t/debug/f
mv d e; mv t t.old
echo "first [$(ls -A e | tr "\n" " ")]"
echo "names $(cat e/a e/b e/sub/c | tr "\n" " ")$(stat -c %h e/a)"
echo "below $(cat t.old/debug/f t.old/debug/deps/f-1 | tr "\n" " ")$(stat -c %h t.old/debug/f)"
[ -e o/out ]; echo "elsewhere $?"
ln e/b e/x; echo "ln $? $(stat -c %h e/a)"
rm e/b e/x; echo "rm $? $(stat -c %h e/a)"
mkdir r; echo three > r/a; ln r/a r/b; mv r r.ro; chmod 555 r.ro
echo "ro $(cat r.ro/a r.ro/b | tr "\n" " ")$(stat -c %h r.ro/b) [$(ls -A r.ro | tr "\n" " ")]"
chmod 755 r.ro
rm -rf e r.ro t.old o; echo "rm -rf $? [$(ls -A | tr "\n" " ")]"
'

set +e
RESULT=$(${PROOT} -l sh -c "${SCENARIO}" sh "${DIR}" 2>&1)
STATUS=$?
set -e

LEFT=$(ls -A "${DIR}" | wc -l)

rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='first [a b sub ]
names one one one 4
below two two 2
elsewhere 1
ln 0 5
rm 0 3
ro three three 2 [a b ]
rm -rf 0 []'

if [ "${RESULT}" != "${EXPECTED}" ] || [ "${LEFT}" -ne 0 ]; then
    echo "${RESULT}"
    echo "left: ${LEFT}"
    exit 1
fi

exit 0
