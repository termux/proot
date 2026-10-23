if [ -z "$(which mcookie)" ] || [ -z "$(which grep)" ] || [ -z "$(which ln)" ] || [ -z "$(which id)" ]; then
    exit 125;
fi

# With -q, PRoot binds the host rootfs to /host-rootfs and /dev/null to
# /etc/ld.so.preload: as root, it would create their placeholders in the
# / and the /etc of the host.
if [ "$(id -u)" -eq 0 ]; then
    exit 125;
fi

# The command given to -q was looked up with realpath(3), which
# dereferences the final component whatever it was asked: a symbolic
# link to a multi-call program -- "false" to coreutils on Termux -- was
# run under the name of that program.

DIR=${TMPDIR:?}/$(mcookie)
mkdir ${DIR}
touch ${DIR}/command ${DIR}/program
chmod +x ${DIR}/command ${DIR}/program
ln -s command ${DIR}/link

# Not through a pipe to "grep -q": PRoot would be killed by SIGPIPE
# before it removes its glue.
set +e
OUTPUT=$(${PROOT} -v 1 -q ${DIR}/link ${DIR}/program 2>&1)
set -e

rm -rf ${DIR}

echo "${OUTPUT}" | grep "^proot info: qemu = ${DIR}/link$"
