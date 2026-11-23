if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which cut)" ] || [ -z "$(which find)" ] || [ -z "$(which grep)" ] || [ -z "$(which sleep)" ]; then
    exit 125;
fi

# The translated path of a socket too long to fit sun_path was replaced
# with a shorter one in the temporary directory of PRoot, which the guest
# path was bound to for the rest of the session.  The socket wasn't
# where the guest expected it: it wasn't listed in its directory, so
# rm -r left it behind, and the binding kept leading there once the
# directory was made again -- a regular file couldn't be created at this
# path anymore (#398).  connect(2) made such a binding too, which hid
# the file already there, and the sockets of other sessions or of the
# host couldn't be reached.  PRoot gives the kernel a path through a
# symbolic link to the directory of the socket instead.
#
# A host path that fills sun_path, with no room for the terminating null
# byte, was given as is: the kernel reports the address of such a socket
# as longer than struct sockaddr_un, which PRoot didn't translate, so
# getsockname(2) gave the guest this host path.  It is given through a
# symbolic link as well now.
#
# A socket whose name is too long for such a link was still bound to a
# shorter path: it is bound to a temporary name in its directory, then
# renamed.  Only when even this doesn't fit sun_path, because of the
# length of the temporary directory of PRoot, is it bound to a shorter
# path, though only once bind(2) succeeded, and not over a file.

DIR=${TMPDIR:?}/$(mcookie | cut -c 1-8)
SCRIPT_DIR=$(dirname "$0")

# The paths in the guest have to fit sun_path, the ones on the host
# mustn't, and the ones through an alias,
# "<temporary directory>/proot-XXXXXX/<name>", have to.  The scenarios
# work in "<guest>/sockets".
if [ ${#DIR} -ge 83 ]; then
    exit 125
fi

GUEST=${DIR}/g
NATIVE=${DIR}/n
HOST=${DIR}/l/$(mcookie)$(mcookie)$(mcookie)
mkdir -p "${GUEST}" "${NATIVE}" "${HOST}"

# The longest name an alias of "<guest>/sockets" takes, and one more
# than this: such a socket is bound to a temporary name, then renamed.
ALIASED=$(printf "%0$((93 - ${#DIR}))d" 0)
RENAMED=$(printf "%0$((95 - ${#DIR}))d" 0)

# A temporary directory so long that such a socket is bound to a
# shorter path, "<temporary directory>/proot-<PID>-XXXXXX".
LONG_TMP=${DIR}/$(printf "%0$((83 - ${#DIR}))d" 0)
mkdir -p "${LONG_TMP}"

# A name that makes "<filled>/sockets/<name>" fill sun_path, whereas
# "<unfilled>/sockets/<name>" doesn't.
FILLED=${DIR}/h12345
UNFILLED=${DIR}/q
FILLING=$(printf "%0$((92 - ${#DIR}))d" 0)
mkdir -p "${FILLED}" "${UNFILLED}"

if ! gcc "${SCRIPT_DIR}/unix_socket_paths.c" -o "${DIR}/unix_socket_paths" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

# The scenarios hold on the host first.
for NAME in ${ALIASED} ${RENAMED} ${FILLING}; do
    "${DIR}/unix_socket_paths" scenarios "${NATIVE}" "${NAME}"
done

BINARIES="${DIR}/unix_socket_paths"
set +e
gcc -m32 "${SCRIPT_DIR}/unix_socket_paths.c" -o "${DIR}/unix_socket_paths-m32" >/dev/null 2>&1 \
&& "${DIR}/unix_socket_paths-m32" scenarios "${NATIVE}" "${ALIASED}" >/dev/null 2>&1
STATUS=$?
set -e
if [ ${STATUS} -eq 0 ]; then
    BINARIES="${BINARIES} ${DIR}/unix_socket_paths-m32"
fi

for BINARY in ${BINARIES}; do
    for NO_SECCOMP in "" PROOT_NO_SECCOMP=1; do
        for NAME in ${ALIASED} ${RENAMED}; do
            env ${NO_SECCOMP} PROOT_TMP_DIR="${DIR}" ${PROOT} -b "${HOST}:${GUEST}" \
                "${BINARY}" scenarios "${GUEST}" "${NAME}"
        done

        env ${NO_SECCOMP} PROOT_TMP_DIR="${LONG_TMP}" ${PROOT} -b "${HOST}:${GUEST}" \
            "${BINARY}" scenarios "${GUEST}" "${RENAMED}" hidden

        env ${NO_SECCOMP} PROOT_TMP_DIR="${DIR}" ${PROOT} -b "${FILLED}:${UNFILLED}" \
            "${BINARY}" scenarios "${UNFILLED}" "${FILLING}"
    done
done

# Wait for the server that prints "ready" in the file $1.
wait_ready() {
    I=0
    while [ ${I} -lt 100 ]; do
        if grep -q ready "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        I=$((I + 1))
    done
    return 1
}

# A socket bound in a session is reached from another one, and is
# where the host expects it, as is a socket bound under a temporary
# name.
for NAME in guest ${RENAMED}; do
    env PROOT_TMP_DIR="${DIR}" ${PROOT} -b "${HOST}:${GUEST}" \
        "${DIR}/unix_socket_paths" serve "${GUEST}" ${NAME} > "${DIR}/server" &
    SERVER=$!
    wait_ready "${DIR}/server"
    test -S "${HOST}/${NAME}"
    env PROOT_TMP_DIR="${DIR}" ${PROOT} -b "${HOST}:${GUEST}" \
        "${DIR}/unix_socket_paths" client "${GUEST}" ${NAME}
    wait ${SERVER}
done

# The host reaches a socket bound in a session.
env PROOT_TMP_DIR="${DIR}" ${PROOT} -b "${HOST}:${GUEST}" \
    "${DIR}/unix_socket_paths" serve "${GUEST}" guest-host > "${DIR}/server" &
SERVER=$!
wait_ready "${DIR}/server"
"${DIR}/unix_socket_paths" client "${HOST}" guest-host
wait ${SERVER}

# A session reaches a socket the host bound.
"${DIR}/unix_socket_paths" serve "${HOST}" host-guest > "${DIR}/server" &
SERVER=$!
wait_ready "${DIR}/server"
env PROOT_TMP_DIR="${DIR}" ${PROOT} -b "${HOST}:${GUEST}" \
    "${DIR}/unix_socket_paths" client "${GUEST}" host-guest
wait ${SERVER}

# The aliases and the temporary names are removed at exit, the sockets
# are left where they were bound, as the kernel does.
LEFT=$(cd "${DIR}" && find . -name 'proot-*' -o -name '.proot-*')
SOCKETS=$(cd "${HOST}" && find . -mindepth 1 | sort | tr '\n' ' ')

rm -rf "${DIR}"

if [ -n "${LEFT}" ] || [ "${SOCKETS}" != "./${RENAMED} ./guest ./guest-host ./host-guest " ]; then
    echo "left: ${LEFT}"
    echo "sockets: ${SOCKETS}"
    exit 1
fi

exit 0
