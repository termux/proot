if [ -z "$(which mcookie)" ] || [ -z "$(which ln)" ] || [ ! -x ${ROOTFS}/bin/open_tree ]; then
    exit 125;
fi

# open_tree(2), Linux 5.2, takes a path like openat(2) does: it must be
# translated, otherwise the kernel gets the guest path.  That fails with
# ENOENT for a path that doesn't exist on the host, and opens a file
# outside of the rootfs for a path that does: open_tree(AT_FDCWD, "/") is
# the host's root directory.  Relative paths are looked up in the working
# directory of the guest, not in the one PRoot was started from, and ".."
# can't leave the rootfs.
#
# The helper compares the returned descriptor with what stat(2) tells about
# the same path, and exits with 125 on kernels without the syscall.

NAME=$(mcookie)
HOST=${ROOTFS}/tmp/${NAME}
GUEST=/tmp/${NAME}
OUTSIDE=${TMPDIR:?}/${NAME}.outside

trap 'rm -rf "${HOST}" "${OUTSIDE}"' EXIT

mkdir "${HOST}" "${HOST}/dir" "${OUTSIDE}"
ln -s dir "${HOST}/link"
ln -s "${GUEST}/dir" "${HOST}/abslink"
ln -s "${OUTSIDE}" "${HOST}/outlink"

CMD="${PROOT} -r ${ROOTFS} /bin/open_tree"
CMD0="${PROOT} -0 -r ${ROOTFS} /bin/open_tree"
CMDW="${PROOT} -w ${GUEST} -r ${ROOTFS} /bin/open_tree"

# Absolute paths (exits with 125 here if the syscall is unknown).
${CMD} -s / / ok
${CMD} -s "${GUEST}/dir" "${GUEST}/dir" ok

# A path that exists only outside of the rootfs is not found.
${CMD} "${OUTSIDE}" ENOENT
${CMD} "${GUEST}/nonexistent" ENOENT
${CMD} "" ENOENT

# Relative to a directory descriptor, and ".." stops at the root of the
# guest.
${CMD} -d "${GUEST}" -s "${GUEST}/dir" dir ok
${CMD} -d "${GUEST}/dir" -s "${GUEST}" .. ok
${CMD} -d "${GUEST}/dir" -s / ../../../../../../.. ok

# An empty path names the directory descriptor itself.
${CMD} -d "${GUEST}/dir" -e -s "${GUEST}/dir" "" ok

# Through symlinks, which are followed unless AT_SYMLINK_NOFOLLOW is set.
# The absolute one is relative to the root of the guest, and the one to a
# path that exists only outside of the rootfs leads nowhere.
${CMD} -s "${GUEST}/dir" "${GUEST}/link" ok
${CMD} -s "${GUEST}/dir" "${GUEST}/abslink" ok
${CMD} "${GUEST}/outlink" ENOENT
${CMD} -n -s "${GUEST}/link" "${GUEST}/link" ok
${CMD} -n -s "${GUEST}/abslink" "${GUEST}/abslink" ok
${CMD} -n -s "${GUEST}/outlink" "${GUEST}/outlink" ok

# Relative to the working directory of the guest, which is not the one of
# the tracee.
${CMDW} -s . . ok
${CMDW} -s "${GUEST}/dir" dir ok
${CMDW} -s "${GUEST}/dir" link ok
${CMDW} -s / ../.. ok
${CMDW} -e -s . "" ok
${CMDW} "" ENOENT

# What the kernel rejects is still rejected.
${CMD} -r "${GUEST}/dir" EINVAL

# Same with -0.
${CMD0} -s / / ok
${CMD0} "${OUTSIDE}" ENOENT
${CMD0} -n -s "${GUEST}/abslink" "${GUEST}/abslink" ok
${CMD0} -d "${GUEST}/dir" -e -s "${GUEST}/dir" "" ok

exit 0
