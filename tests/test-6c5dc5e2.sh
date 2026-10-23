if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ]; then
    exit 125;
fi

# hidden_files took the -errno of a failed getdents(2) for the number of
# bytes it returned, then copied that many bytes into a buffer of the
# size the tracee passed: PRoot crashed whenever a listing failed, for
# instance on a file that is not a directory.

DIR=${TMPDIR:?}/$(mcookie).hidden
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}"
touch "${DIR}/file"

if ! gcc "${SCRIPT_DIR}/getdents.c" -o "${DIR}/getdents" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

set +e
EXPECTED=$("${DIR}/getdents" "${DIR}/file" 2>&1)
RESULT=$(${PROOT} -H "${DIR}/getdents" "${DIR}/file" 2>&1)
set -e

rm -rf "${DIR}"

# Every listing fails with ENOTDIR, as it does without PRoot.
echo "${EXPECTED}" | grep -q '^getdents64 error 20$'
test "${RESULT}" = "${EXPECTED}"
