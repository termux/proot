if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which head)" ]; then
    exit 125;
fi

# hidden_files parsed the records of getdents(2) with the struct
# linux_dirent of PRoot, whose d_ino and d_off are a word of the ABI of
# PRoot.  For a 32-bit tracee of a 64-bit PRoot it read d_reclen from
# the middle of d_name: hidden entries were listed, listings were
# mangled, and PRoot or the tracee looped forever.

DIR=${TMPDIR:?}/$(mcookie).hidden
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/list"

# A hidden entry this long fills the smallest buffer of the helper on
# its own, which makes hidden_files reissue getdents(2).
PADDING=$(printf '%064d' 0)
for I in 1 2 3; do
    touch "${DIR}/list/.proot${I}${PADDING}" "${DIR}/list/visible${I}"
done
touch "${DIR}/list/.proot"

# PRoot looped without ever looking at SIGTERM.
TIMEOUT=$(which timeout || true)
PROBE=
if [ -n "${TIMEOUT}" ]; then
    PROBE="${TIMEOUT} -s KILL 10"
    TIMEOUT="${TIMEOUT} -s KILL 60"
fi

# Only the helpers the system runs to the end: on Termux, "gcc -m32"
# builds 32-bit programs that crash or spin at startup.
runs() {
    ${PROBE} "$1" "${DIR}" >/dev/null 2>&1
    [ $? -le 1 ]
}

HELPERS=
if gcc "${SCRIPT_DIR}/getdents.c" -o "${DIR}/getdents" >/dev/null 2>&1 && runs "${DIR}/getdents"; then
    HELPERS="${DIR}/getdents"
fi
if gcc -m32 "${SCRIPT_DIR}/getdents.c" -o "${DIR}/getdents-m32" >/dev/null 2>&1 && runs "${DIR}/getdents-m32"; then
    HELPERS="${HELPERS} ${DIR}/getdents-m32"
fi
if [ -z "${HELPERS}" ]; then
    rm -rf "${DIR}"
    exit 125
fi

STATUS=0
for HELPER in ${HELPERS}; do
    # Every listing shows what it does without PRoot, minus the hidden
    # entries.
    EXPECTED=$("${HELPER}" "${DIR}/list" 2>&1 | grep -v '^[a-z0-9]* \.proot')
    RESULT=$(${TIMEOUT} ${PROOT} -H "${HELPER}" "${DIR}/list" 2>&1 | head -n 1000)
    if [ "${RESULT}" != "${EXPECTED}" ]; then
        STATUS=1
    fi
done

rm -rf "${DIR}"

exit ${STATUS}
