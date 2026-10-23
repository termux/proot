if [ ! -x /bin/true ] || [ -z `which id` ] || [ -z `which grep` ] || [ -z `which env` ] || [ -z `which chown` ] || [ -z `which chroot` ] || [ -z `which mcookie` ]; then
    exit 125;
fi

if [ `id -u` -eq 0 ]; then
    exit 125;
fi

# A file of this test rather than /root, which Android doesn't have.
FILE=${TMPDIR:?}/$(mcookie)
trap 'rm -f "${FILE}"' EXIT
touch ${FILE}

# Bionic shows the auxiliary vector only since Android 15.
SHOW_AUXV=$(env LD_SHOW_AUXV=1 /bin/true | grep '^AT_UID' || true)

${PROOT} -i 123:456 id -u | grep ^123$
${PROOT} -i 123:456 id -g | grep ^456$

# Bionic puts no colon after the names, glibc does.
if [ -n "${SHOW_AUXV}" ]; then
    ${PROOT} -i 123:456 env LD_SHOW_AUXV=1 /bin/true | grep '^AT_UID:\{0,1\}[[:space:]]*123$'
    ${PROOT} -i 123:456 env LD_SHOW_AUXV=1 /bin/true | grep '^AT_EUID:\{0,1\}[[:space:]]*123$'
    ${PROOT} -i 123:456 env LD_SHOW_AUXV=1 /bin/true | grep '^AT_GID:\{0,1\}[[:space:]]*456$'
    ${PROOT} -i 123:456 env LD_SHOW_AUXV=1 /bin/true | grep '^AT_EGID:\{0,1\}[[:space:]]*456$'
fi

! ${PROOT} -i 123:456 chown 0:0 ${FILE}
[ $? -eq 0 ]

! chroot / /bin/true
EXPECTED=$?

! ${PROOT} -i 123:456 chroot / /bin/true
[ $? -eq ${EXPECTED} ]

# Android has no /tmp before version 15.
! ${PROOT} -i 123:456 chroot /dev/.. /bin/true
[ $? -eq ${EXPECTED} ]

! ${PROOT} -i 123:456 chroot /dev /bin/true
[ $? -eq 0 ]

${PROOT} -0 id -u | grep ^0$
${PROOT} -0 id -g | grep ^0$
${PROOT} -0 chown 0:0 ${FILE}
${PROOT} -0 chroot / /bin/true
${PROOT} -0 chroot /dev/.. /bin/true

if [ -n "${SHOW_AUXV}" ]; then
    ${PROOT} -0 env LD_SHOW_AUXV=1 /bin/true | grep '^AT_UID:\{0,1\}[[:space:]]*0$'
    ${PROOT} -0 env LD_SHOW_AUXV=1 /bin/true | grep '^AT_EUID:\{0,1\}[[:space:]]*0$'
    ${PROOT} -0 env LD_SHOW_AUXV=1 /bin/true | grep '^AT_GID:\{0,1\}[[:space:]]*0$'
    ${PROOT} -0 env LD_SHOW_AUXV=1 /bin/true | grep '^AT_EGID:\{0,1\}[[:space:]]*0$'
fi
