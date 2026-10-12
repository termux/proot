if [ -z "$(which mcookie)" ] || [ -z "$(which stat)" ] || [ -z "$(which ln)" ] || [ ! -x ${ROOTFS}/bin/fchmodat2 ]; then
    exit 125;
fi

# fchmodat2(2), Linux 6.6, takes a path like fchmodat(2) does: it must be
# translated, otherwise the kernel gets the guest path.  That fails with
# ENOENT for a path that doesn't exist on the host, and changes a file
# outside of the rootfs for a path that does.  glibc 2.39+ uses it for
# fchmodat(..., AT_SYMLINK_NOFOLLOW).
#
# With -0 the permissions of every path component are forced to rwx during
# the translation, and the mode requested for the last one is restored
# afterwards.  There is nothing to restore for a symlink with
# AT_SYMLINK_NOFOLLOW: the syscall fails with EOPNOTSUPP and the mode of the
# file it points to must not change.
#
# The helper exits with 125 on kernels without the syscall.

NAME=$(mcookie)
HOST=${ROOTFS}/tmp/${NAME}
GUEST=/tmp/${NAME}
OUTSIDE=/tmp/${NAME}.outside

trap 'rm -rf "${HOST}" "${OUTSIDE}"' EXIT

mkdir "${HOST}" "${OUTSIDE}"
chmod 755 "${OUTSIDE}"
echo content > "${HOST}/file"
ln -s file "${HOST}/link"
ln -s "${GUEST}/file" "${HOST}/abslink"

CMD="${PROOT} -b /proc -r ${ROOTFS} /bin/fchmodat2"
CMD0="${PROOT} -0 -b /proc -r ${ROOTFS} /bin/fchmodat2"

# Absolute path (exits with 125 here if the syscall is unknown).
chmod 644 "${HOST}/file"
${CMD} "${GUEST}/file" 600 ok
[ "$(stat -c %a "${HOST}/file")" = "600" ]

# Relative to a directory descriptor.
${CMD} -d "${GUEST}" file 640 ok
[ "$(stat -c %a "${HOST}/file")" = "640" ]

# Through symlinks: relative, then absolute in the guest.
${CMD} "${GUEST}/link" 620 ok
[ "$(stat -c %a "${HOST}/file")" = "620" ]

${CMD} "${GUEST}/abslink" 610 ok
[ "$(stat -c %a "${HOST}/file")" = "610" ]

# AT_SYMLINK_NOFOLLOW on a regular file changes it.
${CMD} -n "${GUEST}/file" 604 ok
[ "$(stat -c %a "${HOST}/file")" = "604" ]

# AT_SYMLINK_NOFOLLOW on a symlink fails and changes nothing.
${CMD} -n "${GUEST}/link" 600 EOPNOTSUPP
${CMD} -n "${GUEST}/abslink" 600 EOPNOTSUPP
[ "$(stat -c %a "${HOST}/file")" = "604" ]

# A path that exists only outside of the rootfs is not found, and is left
# alone.
${CMD} "${OUTSIDE}" 700 ENOENT
[ "$(stat -c %a "${OUTSIDE}")" = "755" ]

${CMD} "${GUEST}/nonexistent" 600 ENOENT

# Same with -0, now for a read-only file whose permissions are overridden.
chmod 444 "${HOST}/file"
${CMD0} "${GUEST}/file" 640 ok
[ "$(stat -c %a "${HOST}/file")" = "640" ]

chmod 444 "${HOST}/file"
${CMD0} -d "${GUEST}" link 600 ok
[ "$(stat -c %a "${HOST}/file")" = "600" ]

chmod 444 "${HOST}/file"
${CMD0} -n "${GUEST}/file" 620 ok
[ "$(stat -c %a "${HOST}/file")" = "620" ]

chmod 444 "${HOST}/file"
${CMD0} -n "${GUEST}/link" 600 EOPNOTSUPP
${CMD0} -n "${GUEST}/abslink" 600 EOPNOTSUPP
[ "$(stat -c %a "${HOST}/file")" = "444" ]

exit 0
