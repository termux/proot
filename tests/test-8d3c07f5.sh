if [ -z "$(which mcookie)" ] || [ -z "$(which busybox)" ]; then
    exit 125;
fi

# PROOT_L2S_DIR names the directory the backing files of faked hard links
# are kept in, and the extension acts on it with raw host syscalls that no
# path translation applies to.  Resolving that name afresh at each of them
# let a tracee replace the directory with a symbolic link -- "rm -rf" and
# "ln -s" on a path inside its own rootfs, no concurrency needed, nothing
# of the host bound in -- and have every backing file created outside the
# rootfs from then on, with content of its choosing.
#
# The directory is opened once, O_NOFOLLOW, and each entry is named
# relative to that descriptor, so the link is refused rather than
# followed.

DIR=${TMPDIR:?}/$(mcookie).l2s
ROOTFS="${DIR}/rootfs"
OUTSIDE="${DIR}/outside"
mkdir -p "${ROOTFS}/bin" "${ROOTFS}/.l2s" "${OUTSIDE}"

# A shell inside the rootfs, so the test needs no binding to run.
cp "$(which busybox)" "${ROOTFS}/bin/busybox"

# The final "ln" is expected to fail: what matters is where it would have
# created the backing file, so its status doesn't stop the test.
MARKER=$(PROOT_L2S_DIR="${ROOTFS}/.l2s" ${PROOT} -l --rootfs="${ROOTFS}" \
    /bin/busybox sh -c '
        echo escaped > /original
        /bin/busybox rm -rf /.l2s
        /bin/busybox ln -s '"${OUTSIDE}"' /.l2s
        /bin/busybox test -L /.l2s && echo READY
        /bin/busybox ln /original /link
    ' 2>/dev/null) || true

ESCAPED=$(ls -A "${OUTSIDE}" | wc -l)

rm -rf "${DIR}"

# The tracee has to have got as far as replacing the directory, or this
# test would pass without having tried anything.
if [ "${MARKER}" != "READY" ]; then
    exit 125;
fi

# Nothing may have been created outside the rootfs.
if [ "${ESCAPED}" != "0" ]; then
    exit 1
fi

exit 0
