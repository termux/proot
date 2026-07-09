if [ -z "$(which mcookie)" ] || [ ! -e /proc/self/fd/0 ] || [ ! -x "${ROOTFS}/bin/true" ]; then
    exit 125;
fi

# Regression test for: spurious binding warnings for proot-distro's default
# -b /proc/self/fd/N:/dev/std* bindings on devices whose guest rootfs has no
# /dev/std* nodes.
#
# After commit f4bb4c4 the /proc/self/fd/N host path was stored verbatim, so
# initialize_binding()'s lstat() reported it as S_IFLNK.  When the guest rootfs
# lacked the target (glue path), build_glue() tried mknod(host, S_IFLNK) -- which
# cannot create a symlink and fails -- yet returned the type anyway (final
# component), so canonicalize() dereferenced a placeholder that was never created.
# readlink(2) returned -1 (== -EPERM), and the guest path could not be sanitized:
#   proot warning: sanitizing the guest path (binding) "/dev/stdin": Operation not permitted
# (likewise for /dev/stdout and /dev/stderr), and the bindings were dropped.
#
# The warning is emitted while initializing the binding, before the guest command
# runs, so /bin/true fully exercises it.  ${ROOTFS} ships no /dev, so the glue
# path that regressed is taken.  The fix coerces the S_IFLNK host to a regular
# file glue placeholder, so the bindings initialize cleanly with no warning.

ERR=/tmp/$(mcookie).err

${PROOT} -b /proc -r ${ROOTFS} \
    -b /proc/self/fd/0:/dev/stdin \
    -b /proc/self/fd/1:/dev/stdout \
    -b /proc/self/fd/2:/dev/stderr \
    /bin/true 2> ${ERR}

if grep -q 'sanitizing the guest path (binding) "/dev/std' ${ERR}; then
    rm -f ${ERR}
    exit 1
fi

rm -f ${ERR}
