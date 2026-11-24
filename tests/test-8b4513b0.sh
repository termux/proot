if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which stat)" ] || [ -z "$(which cat)" ] || [ -z "$(which ls)" ]; then
    exit 125;
fi

# The names of a file link2symlink made hard links of all go through
# the intermediate of its chain, ".l2s.<name>0001", to its final file,
# ".l2s.<name>0001.<count>".  Neither is listed anymore, but both can
# still be named, by an archive made by an older PRoot for instance:
# removing one by its name, moving it away, or replacing it left every
# name of the file dangling, and what was left of the chain behind.
# Their removal is one more name gone, which isn't counted, and they
# can't be moved or replaced, unless onto another name of their own
# file, which does nothing.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/l2s" "${DIR}/next" "${DIR}/separate"

if ! gcc "${SCRIPT_DIR}/link.c" -o "${DIR}/link" >/dev/null 2>&1 \
|| ! gcc "${SCRIPT_DIR}/renameat2.c" -o "${DIR}/renameat2" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

# Kernels older than 3.15 have no renameat2(2).
: > "${DIR}/p"
if ! "${DIR}/renameat2" "${DIR}/p" "${DIR}/q" 0; then
    rm -rf "${DIR}"
    exit 125
fi

# Note: renameat2 exits with 1 on error.
SCENARIO='
cd "$1" || exit 1
I=$2
F=$2.0003
echo data > a; ../link a b; ../link a c; echo other > x
../renameat2 x "$I" 0; echo "x onto intermediate $?"
../renameat2 "$I" y 0; echo "intermediate away $?"
../renameat2 x "$F" 0; echo "x onto final $?"
../renameat2 "$F" y 0; echo "final away $?"
../renameat2 x "$I" 2; echo "exchange $?"
../renameat2 "$I" y 1; echo "noreplace away $?"
../renameat2 a "$I" 0; echo "a onto intermediate $?"
../renameat2 "$F" b 0; echo "final onto b $?"
rm "$I"; echo "rm intermediate $?"
rm "$F"; echo "rm final $?"
echo "names [$(ls -A | tr "\n" " ")] $(cat a b c x | tr "\n" " ")$(stat -c %h a)"
rm a b c; echo "rm names $? [$(ls -A | tr "\n" " ")]"
'

set +e
RESULT=$(
${PROOT} -l sh -c "${SCENARIO}" sh "${DIR}/next" .l2s.a0001 2>&1
PROOT_L2S_DIR="${DIR}/l2s" ${PROOT} -l sh -c "${SCENARIO}" sh "${DIR}/separate" ../l2s/.l2s.a0001 2>&1
)
STATUS=$?
set -e

LEFT=$(ls -A "${DIR}/next" "${DIR}/separate" "${DIR}/l2s" | grep -c '\.l2s\.' || true)

cd /
rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='x onto intermediate 1
intermediate away 1
x onto final 1
final away 1
exchange 1
noreplace away 1
a onto intermediate 0
final onto b 0
rm intermediate 0
rm final 0
names [a b c x ] data data data other 3
rm names 0 [x ]'

if [ "${RESULT}" != "${EXPECTED}
${EXPECTED}" ] || [ "${LEFT}" -ne 0 ]; then
    echo "${RESULT}"
    echo "left: ${LEFT}"
    exit 1
fi

exit 0
