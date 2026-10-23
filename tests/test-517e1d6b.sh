if [ -z `which true` ] || [ -z `which realpath` ] || [ -z `which grep` ] || [ -z `which id` ] || [ -z `which env` ] || [ ! -x  ${ROOTFS}/bin/puts_proc_self_exe ]; then
    exit 125;
fi

# With -q, PRoot binds the host rootfs to /host-rootfs and /dev/null to
# /etc/ld.so.preload: as root, it would create their placeholders in the
# / and the /etc of the host.
if [ `id -u` -eq 0 ]; then
    exit 125;
fi

TRUE=$(realpath $(which true))

env PROOT_FORCE_FOREIGN_BINARY=1 ${PROOT} -q ${ROOTFS}/bin/puts_proc_self_exe ${TRUE} | grep ^${TRUE}$
