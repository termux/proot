if [ -z `which mcookie` ] || [ -z `which mkdir` ] || [ -z `which bash` ] || [ -z `which grep` ] || [ -z `which rm` ] || [ -z `which chmod` ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)

# A guest path that doesn't exist, in a directory that isn't writable --
# as "/foo" was.  Root can write there anyway, so the placeholder PRoot
# creates then lies in a directory of this test, not in the root of the
# host.
TOP=${TMPDIR:?}/$(mcookie)
trap 'chmod u+w "${TOP}"; rm -fr "${TMP}" "${TOP}"' EXIT

mkdir -p ${TMP} ${TOP}
chmod a-w ${TOP}
cd ${TMP}

${PROOT} -b ${PWD}:${TOP}/foo -w ${TOP}/foo bash -c 'pwd' | grep "^${TOP}/foo$"
