if [ -z "$(which mcookie)" ] || [ ! -x ${ROOTFS}/bin/open_tree ]; then
    exit 125;
fi

# PRoot turns mount(2), umount(2) and pivot_root(2) into bindings, and
# has nothing for the file descriptor based mount API, Linux 5.2 and later.
# Passed to the kernel, those calls would fail with EPERM, or really mount
# behind the bindings' back when PRoot runs as root.  They must fail with
# ENOSYS, as on kernels that don't have them: libmount then falls back to
# mount(2).  The same goes for open_tree(2) with OPEN_TREE_CLONE, since
# the tree it returns is good for move_mount(2) only.
#
# This test can't tell a kernel without these syscalls from PRoot hiding
# them, so it passes there too.

NAME=$(mcookie)
HOST=${ROOTFS}/tmp/${NAME}
GUEST=/tmp/${NAME}

trap 'rm -rf "${HOST}"' EXIT

mkdir "${HOST}"

CMD="${PROOT} -r ${ROOTFS} /bin/open_tree"
CMD0="${PROOT} -0 -r ${ROOTFS} /bin/open_tree"

for call in fsopen fsconfig fsmount fspick move_mount mount_setattr open_tree_attr; do
    ${CMD} -m ${call}
    ${CMD0} -m ${call}
done

${CMD} -c / ENOSYS
${CMD} -c "${GUEST}" ENOSYS
${CMD} -c -r "${GUEST}" ENOSYS
${CMD} -c -e "" ENOSYS
${CMD0} -c "${GUEST}" ENOSYS

exit 0
