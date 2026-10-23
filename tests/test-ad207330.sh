if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which awk)" ]; then
    exit 125;
fi

# A faked hard link is a symbolic link on disk, and getdents(2) reported
# it as such -- DT_LNK -- while lstat(2) reports the file it stands for.
# Programs that trust d_type ("find -type f", ripgrep, Rust's
# DirEntry::file_type(), Python's DirEntry.is_symlink()) skipped every
# name of a hard-linked file, or tripped over the contradiction.

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/l2s" "${DIR}/sibling" "${DIR}/separate"

if ! gcc "${SCRIPT_DIR}/getdents.c" -o "${DIR}/getdents" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

SCENARIO='
cd "$1" || exit 1
echo content > file
ln file link
ln -s file symlink
mkdir directory
"$2" .
'

set +e
RESULT=$(${PROOT} -l sh -c "${SCENARIO}" sh "${DIR}/sibling" "${DIR}/getdents" 2>&1
         PROOT_L2S_DIR="${DIR}/l2s" ${PROOT} -l sh -c "${SCENARIO}" sh "${DIR}/separate" "${DIR}/getdents" 2>&1)
set -e

rm -rf "${DIR}"

# Every listing -- getdents64(2), getdents(2) where the ABI has it, with
# a large buffer or a buffer of a single entry -- reports the type
# lstat(2) does for the names the tracee created.  Intermediates are
# left out: lstat(2) and statx(2) don't agree on them.
echo "${RESULT}" | awk '
$2 == "file" || $2 == "link" { if ($3 == 8 && $4 == 8) regular++; else bad++ }
$2 == "symlink"              { if ($3 == 10 && $4 == 10) symlinks++; else bad++ }
$2 == "directory"            { if ($3 == 4 && $4 == 4) directories++; else bad++ }
END { exit !(bad == 0 && regular > 0 && regular == 2 * symlinks && symlinks == directories) }
'
