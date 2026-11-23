if [ -z "$(which mcookie)" ] || [ -z "$(which stat)" ] || [ -z "$(which ln)" ] || [ -z "$(which cp)" ] || [ -z "$(which chmod)" ]; then
    exit 125;
fi

# With -0 the permissions of the path components are forced to rwx during
# the translation, and restored afterwards; stat(2) is the exception, it
# needs no permission on the file it reports about.  The file a final
# symlink leads to was taken for an intermediate component, though: stat
# -L, cp -pL, ... saw it as 0640 instead of 0440, as did any stat(2) of a
# faked hard link (-l), always a symlink on the host.  And when the
# directory of this file can't be searched, chmod(2) through the symlink
# "succeeded" but the mode was put back as it was afterwards.

DIR=${TMPDIR:?}/$(mcookie)
mkdir -p "${DIR}/dir"

echo content > "${DIR}/file"
chmod 440 "${DIR}/file"
ln -s file "${DIR}/link"
ln -s link "${DIR}/link2"

echo content > "${DIR}/dir/file"
chmod 440 "${DIR}/dir/file"
ln -s dir/file "${DIR}/dirlink"

RESULT=$(${PROOT} -0 stat -L -c %a "${DIR}/link" "${DIR}/link2" "${DIR}/dirlink" | tr '\n' ' ')
[ "${RESULT}" = "440 440 440 " ] || { echo "stat -L: ${RESULT}"; rm -rf "${DIR}"; exit 1; }

${PROOT} -0 cp -pL "${DIR}/link" "${DIR}/copy"
RESULT=$(stat -c %a "${DIR}/copy")
[ "${RESULT}" = "440" ] || { echo "cp -pL: ${RESULT}"; rm -rf "${DIR}"; exit 1; }

# chmod(2) through a symlink to a file in a directory nobody can search.
chmod 0 "${DIR}/dir"
${PROOT} -0 chmod 600 "${DIR}/dirlink"
chmod 755 "${DIR}/dir"
RESULT=$(stat -c %a "${DIR}/dir/file")
[ "${RESULT}" = "600" ] || { echo "chmod: ${RESULT}"; rm -rf "${DIR}"; exit 1; }

# Faked hard links.
RESULT=$(${PROOT} -0 -l sh -c "ln ${DIR}/file ${DIR}/hardlink && stat -L -c %a ${DIR}/file ${DIR}/hardlink" | tr '\n' ' ')
[ "${RESULT}" = "440 440 " ] || { echo "-l: ${RESULT}"; rm -rf "${DIR}"; exit 1; }

rm -rf "${DIR}"
exit 0
