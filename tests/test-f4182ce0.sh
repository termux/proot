if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which readlink)" ]; then
    exit 125;
fi

# link(2) doesn't follow symbolic links, and link2symlink moved an
# ordinary one as if it were a file, under the name its content spells
# followed by the suffixes: into the current directory of PRoot for a
# relative content, anywhere on the host for an absolute one.  Both
# names were left pointing to these new files.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/l2s" "${DIR}/outside"

if ! gcc "${SCRIPT_DIR}/link.c" -o "${DIR}/link" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

SCENARIO='
cd "$1" || exit 1
echo data > file
ln -s file relative
"$2" relative relative-link; echo "relative $? $(readlink relative) $(readlink relative-link) $(cat relative-link)"
ln -s "$3/target" absolute
"$2" absolute absolute-link; echo "absolute $? $(readlink absolute-link)"
"$2" relative relative-link; echo "exists $?"
'

for MODE in sibling separate; do
    mkdir -p "${DIR}/${MODE}" "${DIR}/cwd-${MODE}"
done

set +e
RESULT=$(cd "${DIR}/cwd-sibling" && ${PROOT} -l sh -c "${SCENARIO}" sh "${DIR}/sibling" "${DIR}/link" "${DIR}/outside" 2>&1
         cd "${DIR}/cwd-separate" && PROOT_L2S_DIR="${DIR}/l2s" ${PROOT} -l sh -c "${SCENARIO}" sh "${DIR}/separate" "${DIR}/link" "${DIR}/outside" 2>&1)
LEFTOVERS=$(ls -A "${DIR}/cwd-sibling" "${DIR}/cwd-separate" "${DIR}/outside" "${DIR}/l2s")
set -e

EXPECTED="relative 0 file file data
absolute 0 ${DIR}/outside/target
exists 17
relative 0 file file data
absolute 0 ${DIR}/outside/target
exists 17"

rm -rf "${DIR}"

# The new name is a symbolic link with the same content, the old one is
# left as it was, and nothing is created anywhere else.
test "${RESULT}" = "${EXPECTED}"
test -z "$(echo "${LEFTOVERS}" | grep -v -e '^$' -e ':$')"
