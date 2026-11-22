if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which grep)" ]; then
    exit 125;
fi

# Where the host denies AF_NETLINK, as Android does to apps, PRoot gives
# the tracees an AF_UNIX socket in place of each NETLINK_ROUTE socket
# and answers what they send on it.  It kept track of these sockets per
# thread, so a thread did not know a socket another one opened after it
# was created, nor the reply to a request another one sent: its recv(2)
# reached the substitute socket, where nothing ever comes, and blocked
# for ever.  Go programs hung that way, goroutines moving from thread to
# thread (#425).  Neither were the copies of a descriptor known, nor the
# descriptors execve(2) closed or dup2(2) replaced forgotten, which got
# the UDP socket reusing such a number answered as netlink.  The
# requests written with write(2) were refused, and a non-blocking socket
# got a blocking substitute.
#
# netlink_deny.so makes the host deny AF_NETLINK to PRoot, as Android
# does, so the emulation is what the scenarios exercise.  32-bit x86
# programs make these syscalls through socketcall(2), which wasn't
# emulated at all: the scenarios run as such programs too, where they
# can be built.

DIR=${TMPDIR:?}/$(mcookie)
SCRIPT_DIR=$(dirname "$0")
mkdir "${DIR}"

if ! gcc -pthread "${SCRIPT_DIR}/netlink_fds.c" -o "${DIR}/netlink_fds" >/dev/null 2>&1 \
|| ! gcc -shared -fPIC "${SCRIPT_DIR}/netlink_deny.c" -o "${DIR}/netlink_deny.so" -ldl >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

# The scenarios hold on the host first, without PRoot, unless the host
# denies netlink to programs as Android does: 125 means no netlink at
# all.
set +e
"${DIR}/netlink_fds" copies >/dev/null 2>&1
STATUS=$?
set -e
if [ ${STATUS} -eq 125 ]; then
    rm -rf "${DIR}"
    exit 125
fi

# Only if the program runs: it prints its usage then.
BINARIES="${DIR}/netlink_fds"
set +e
gcc -m32 -pthread "${SCRIPT_DIR}/netlink_fds.c" -o "${DIR}/netlink_fds-m32" >/dev/null 2>&1 \
&& "${DIR}/netlink_fds-m32" >/dev/null 2>&1
STATUS=$?
set -e
if [ ${STATUS} -eq 2 ]; then
    BINARIES="${BINARIES} ${DIR}/netlink_fds-m32"
fi

for BINARY in ${BINARIES}; do
    for SCENARIO in threads copies forks writes nonblocking exec thread-exec; do
        for NO_SECCOMP in "" PROOT_NO_SECCOMP=1; do
            set +e
            OUTPUT=$(env ${NO_SECCOMP} LD_PRELOAD="${DIR}/netlink_deny.so" \
                         ${PROOT} -v 1 "${BINARY}" ${SCENARIO} 2>&1)
            STATUS=$?
            set -e
            if [ ${STATUS} -ne 0 ] || ! echo "${OUTPUT}" | grep -q 'AF_NETLINK .* denied by host'; then
                echo "${OUTPUT}"
                rm -rf "${DIR}"
                exit 1
            fi
        done
    done
done

rm -rf "${DIR}"
