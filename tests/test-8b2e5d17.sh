if [ ! -x ${ROOTFS}/bin/unix_socket ] || [ -z "$(which mcookie)" ] || [ -z "$(which env)" ] || [ -z "$(which find)" ]; then
    exit 125;
fi

# A translated socket path too long for sun_path is replaced with a
# shorter one in the temporary directory of PRoot, which the guest path
# gets bound to.  The comment said this alias was removed along with the
# binding, but nothing removed it: each socket bound to such a path and
# not removed by the program itself stayed there forever.

DIR=${TMPDIR:?}/$(mcookie)
NAME=$(mcookie)$(mcookie)$(mcookie)
mkdir -p ${DIR}/guest

# The alias has to fit sun_path: "<temporary directory>/proot-<PID>-XXXXXX".
ALIAS=${DIR}/proot-4194304-XXXXXX
if [ ${#ALIAS} -gt 108 ]; then
    rm -rf ${DIR}
    exit 125
fi

# Twice, the second session can't reach the socket of the first one.
for SESSION in 1 2; do
    env PROOT_TMP_DIR=${DIR} ${PROOT} -r ${ROOTFS} -b ${DIR}/guest:/tmp /bin/unix_socket /tmp/${NAME}
done

RESULT=$(find ${DIR} -mindepth 1)

rm -rf ${DIR}

if [ "${RESULT}" != "${DIR}/guest" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
