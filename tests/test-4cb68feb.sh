if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which grep)" ]; then
    exit 125;
fi

# On aarch64, one flag told PRoot both the ABI of the syscalls of a
# tracee and the layout of its registers -- ARM EABI or AArch64 -- and
# it changed only once the execve(2) of a program of the other class had
# returned.  The kernel reports the registers of the new program at the
# exit stage already, so fake_id0 and kompat read the stack pointer from
# the wrong place and silently gave up adjusting the ELF auxiliary
# vectors: 32-bit ARM programs got their actual credentials under -0 and
# the vDSO under -k.  The flag was also set to the class of the program
# when execve(2) failed, which crashed the process that made it.
#
# The scenarios run as 32-bit programs where they can be built: x86 ones
# on x86_64 hosts, ARM ones on aarch64 hosts with a cross compiler.

DIR=${TMPDIR:?}/$(mcookie)
SCRIPT_DIR=$(dirname "$0")
mkdir "${DIR}"

NATIVE=${DIR}/auxv_ids
M32=${DIR}/auxv_ids-m32

PROBE=$(which timeout || true)
if [ -n "${PROBE}" ]; then
    PROBE="${PROBE} -s KILL 10"
fi

# Only the helpers that work: on Termux, "gcc -m32" builds 32-bit
# programs that crash or spin at startup.  They run under PRoot, the
# seccomp policy of Android kills glibc ones otherwise.
runs() {
    ${PROBE} ${PROOT} "$1" >/dev/null 2>&1
}

if ! gcc "${SCRIPT_DIR}/auxv_ids.c" -o "${NATIVE}" >/dev/null 2>&1 || ! runs "${NATIVE}"; then
    rm -rf "${DIR}"
    exit 125
fi

for COMPILE in "gcc -m32 -static" "gcc -m32" "arm-linux-gnueabihf-gcc -static"; do
    if ${COMPILE} "${SCRIPT_DIR}/auxv_ids.c" -o "${M32}" >/dev/null 2>&1 && runs "${M32}"; then
        break
    fi
    rm -f "${M32}"
done

if [ ! -e "${M32}" ]; then
    rm -rf "${DIR}"
    exit 125
fi

for SECCOMP in on off; do
    if [ ${SECCOMP} = off ]; then
        export PROOT_NO_SECCOMP=1
    fi

    # A failed execve(2) of the other class comes first in the last two.
    for HELPER in "${M32}" "${NATIVE} exec ${M32}" "${M32} exec ${NATIVE}"; do
        ${PROOT} -0 ${HELPER} | grep '^uid=0 euid=0 gid=0 egid=0 '
        ${PROOT} -i 123:456 ${HELPER} | grep '^uid=123 euid=123 gid=456 egid=456 '
        ${PROOT} -k 6.17.0 ${HELPER} | grep ' vdso=0$'
    done
done

rm -rf "${DIR}"
