if [ -z `which ls` ] || [ -z `which mcookie` ] || [ -z `which chmod` ]; then
    exit 125;
fi

# A guest path that doesn't exist, in a directory that isn't writable --
# as "/x" was.  Root can write there anyway, so the placeholder PRoot
# creates then lies in a directory of this test, not in the root of the
# host.
TMP=${TMPDIR:?}/$(mcookie)
trap 'chmod u+w "${TMP}"; rm -fr "${TMP}"' EXIT

mkdir ${TMP}
chmod a-w ${TMP}

${PROOT} -b /etc:${TMP}/x ls -la ${TMP}/x
