if [ ! -x ${ROOTFS}/bin/fork_regs ]; then
    exit 125;
fi

# Android's app seccomp policy raises SIGSYS on fork(2) on x86_64, where
# musl calls it directly, so PRoot runs it as clone(2) instead.  clone(2)
# takes arguments in registers that the kernel preserves across fork(2):
# the parent and the child must both get back the values these registers
# had before the syscall, not the arguments PRoot put there.
#
# "fork_regs trap" runs PRoot under such a policy.  fork_regs exits with
# 125 on architectures without fork(2).

${ROOTFS}/bin/fork_regs trap ${PROOT} -r ${ROOTFS} /bin/fork_regs
env PROOT_NO_SECCOMP=1 ${ROOTFS}/bin/fork_regs trap ${PROOT} -r ${ROOTFS} /bin/fork_regs
