if [ -z "$(which mcookie)" ] || [ -z "$(which env)" ] || [ -z "$(which sh)" ]; then
    exit 125;
fi

# PRoot looked the program to launch up in the guest, then turned the
# host path it led to back into a guest path: not always the one it was
# found at, since the host path of a binding is reachable through its
# guest path too, and the most specific binding won.  With "-b /bin:X"
# on Ubuntu 26.04, "test" became "X/test", and the symbolic link to
# "../lib/cargo/bin/coreutils/test" there led nowhere.

DIR=${TMPDIR:?}/$(mcookie)
mkdir -p "${DIR}/bin" "${DIR}/lib" "${DIR}/alias/bin" "${DIR}/alias/lib"
printf '#!%s\necho "$0"\n' "$(which sh)" > "${DIR}/lib/program"
chmod +x "${DIR}/lib/program"
ln -s ../lib/program "${DIR}/bin/program"

set +e
RESULT=$(
    ${PROOT} -b "${DIR}/bin:${DIR}/alias/bin" "${DIR}/bin/program"
    env PATH="${DIR}/bin:${PATH}" ${PROOT} -b "${DIR}/bin:${DIR}/alias/bin" program
    ${PROOT} -b "${DIR}/lib:${DIR}/alias/lib" "${DIR}/lib/program"
)
set -e

rm -rf "${DIR}"

EXPECTED="${DIR}/bin/program
${DIR}/bin/program
${DIR}/lib/program"

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
