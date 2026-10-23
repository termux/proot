if [ -z `which ls` ] || [ -z `which mcookie` ] || [ -z `which chmod` ] || [ -z `which grep` ]; then
    exit 125;
fi

# A guest path that doesn't exist, in a directory that isn't writable --
# as "/x" was.  Root can write there anyway, so the placeholder PRoot
# creates then lies in a directory of this test, not in the root of the
# host.  The directory bound is the test's own too: an Android app can't
# list every entry of /etc.
TMP=${TMPDIR:?}/$(mcookie)
SRC=${TMPDIR:?}/$(mcookie)
trap 'chmod u+w "${TMP}"; rm -fr "${TMP}" "${SRC}"' EXIT

mkdir ${TMP} ${SRC}
touch ${SRC}/file
chmod a-w ${TMP}

${PROOT} -b ${SRC}:${TMP}/x ls -la ${TMP}/x | grep -w file
