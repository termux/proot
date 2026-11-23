if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which id)" ]; then
    exit 125;
fi

# 32-bit x86 programs make their socket syscalls through socketcall(2).
# fake_id0 didn't fake the credentials getsockopt(SO_PEERCRED) reports
# when made that way, and read the arguments of socketcall(2) as words
# of PRoot: for such a program of a 64-bit PRoot, sendmsg(2) failed with
# EFAULT, the program blocked waiting for what was never sent.

DIR=${TMPDIR:?}/$(mcookie)
SCRIPT_DIR=$(dirname "$0")
mkdir "${DIR}"

TIMEOUT=$(which timeout || true)
PROBE=
if [ -n "${TIMEOUT}" ]; then
    PROBE="${TIMEOUT} -s KILL 10"
    TIMEOUT="${TIMEOUT} -s KILL 60"
fi

# Only the helpers that work: on Termux, "gcc -m32" builds 32-bit
# programs that crash or spin at startup.
runs() {
    ${PROBE} ${PROOT} "$1" >/dev/null 2>&1
}

HELPERS=
if gcc "${SCRIPT_DIR}/socket_creds.c" -o "${DIR}/socket_creds" >/dev/null 2>&1 \
&& runs "${DIR}/socket_creds"; then
    HELPERS="${DIR}/socket_creds"
fi
if gcc -m32 "${SCRIPT_DIR}/socket_creds.c" -o "${DIR}/socket_creds-m32" >/dev/null 2>&1 \
&& runs "${DIR}/socket_creds-m32"; then
    HELPERS="${HELPERS} ${DIR}/socket_creds-m32"
fi
if [ -z "${HELPERS}" ]; then
    rm -rf "${DIR}"
    exit 125
fi

MY_UID=$(id -u)
MY_GID=$(id -g)

check() {
    EXPECTED=$1
    shift
    RESULT=$(${TIMEOUT} "$@" 2>&1)
    test "${RESULT}" = "${EXPECTED}
sent"
}

for SECCOMP in on off; do
    if [ ${SECCOMP} = off ]; then
        export PROOT_NO_SECCOMP=1
    fi

    for HELPER in ${HELPERS}; do
        check "peer uid=0 gid=0" ${PROOT} -0 ${HELPER}
        check "peer uid=123 gid=456" ${PROOT} -i 123:456 ${HELPER}
        check "peer uid=${MY_UID} gid=${MY_GID}" ${PROOT} ${HELPER}
    done
done

rm -rf "${DIR}"
