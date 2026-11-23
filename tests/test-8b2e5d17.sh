if [ ! -x ${ROOTFS}/bin/unix_socket ] || [ -z "$(which mcookie)" ] || [ -z "$(which env)" ] || [ -z "$(which find)" ]; then
    exit 125;
fi

# A translated socket path too long for sun_path is given to the kernel
# through a symbolic link to its directory, and when the name of the
# socket is too long for this, the socket is bound to a temporary name
# in this directory, then renamed (test-5e7a398d).  Unless the temporary
# directory of PRoot is too long for this too, as here: the socket is
# bound to a shorter path in this temporary directory then, which the
# guest path gets bound to.  The comment said this file was removed
# along with the binding, but nothing removed it: each socket bound to
# such a path and not removed by the program itself stayed there
# forever.

DIR=${TMPDIR:?}/$(mcookie)
NAME=$(mcookie)$(mcookie)$(mcookie)
mkdir -p ${DIR}/guest

# "<temporary directory>/proot-XXXXXX/.proot-XXXXXX" mustn't fit
# sun_path, along with a terminating null byte, whereas the shorter
# path, "<temporary directory>/proot-<PID>-XXXXXX", has to.
if [ ${#DIR} -ge 82 ]; then
    rm -rf ${DIR}
    exit 125
fi
TMP=${DIR}/$(printf "%0$((83 - ${#DIR}))d" 0)
mkdir ${TMP}

# Twice, the second session can't reach the socket of the first one.
for SESSION in 1 2; do
    env PROOT_TMP_DIR=${TMP} ${PROOT} -r ${ROOTFS} -b ${DIR}/guest:/tmp /bin/unix_socket /tmp/${NAME}
done

RESULT=$(find ${TMP} ${DIR}/guest -mindepth 1)

rm -rf ${DIR}

if [ -n "${RESULT}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
