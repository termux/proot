if [ -z "$(which mcookie)" ] || [ -z "$(which tar)" ] || [ -z "$(which ln)" ] || [ -z "$(which stat)" ] || [ -z "$(which find)" ] || [ -z "$(which readlink)" ] || [ -z "$(which grep)" ] || [ -z "$(which cat)" ]; then
    exit 125;
fi

# Programs that walk a directory where link2symlink made hard links
# meet the intermediate symbolic link of each file, ".l2s.<name>0001".
# The stat(2) family reported it as the file it points to, but statx(2),
# getdents(2) and readlink(2) as the symbolic link it is, and open(2)
# with O_NOFOLLOW followed none: tar(1), hence dpkg-deb -b, failed with
# ELOOP.  It is one more name of its file to every syscall now.

DIR=${TMPDIR:?}/$(mcookie)
mkdir -p "${DIR}/tree/sub" "${DIR}/extracted"
echo hello > "${DIR}/tree/a"

${PROOT} -l ln "${DIR}/tree/a" "${DIR}/tree/b"
${PROOT} -l ln "${DIR}/tree/a" "${DIR}/tree/sub/c"

INTERMEDIATE=${DIR}/tree/.l2s.a0001
test -L "${INTERMEDIATE}"

LC_ALL=C ${PROOT} -l stat -c "%F %h" "${INTERMEDIATE}" | grep -x "regular file 3"
${PROOT} -l find "${DIR}/tree" -name .l2s.a0001 -type f | grep -x "${INTERMEDIATE}"
if ${PROOT} -l readlink "${INTERMEDIATE}"; then
    exit 1
fi

${PROOT} -l tar -C "${DIR}" -cf "${DIR}/archive.tar" tree

# Each name is the same file: none is archived as a symbolic link, which
# would point into this tree.
if tar -tvf "${DIR}/archive.tar" | grep -v '^[dh-]'; then
    exit 1
fi

# Android denies hard links to apps.
${PROOT} -l tar -C "${DIR}/extracted" -xf "${DIR}/archive.tar"
test "$(cat "${DIR}/extracted/tree/b" "${DIR}/extracted/tree/sub/c" "${DIR}/extracted/tree/.l2s.a0001")" = "hello
hello
hello"

rm -rf "${DIR}"
