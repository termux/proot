if [ -z `which mcookie` ] || [ -z `which echo` ] || [ -z `which rm` ] || [ -z `which touch` ] || [ -z `which chmod` ] || [ -z `which grep` ] || [ -z `which id` ]; then
    exit 125;
fi

# With -q, PRoot binds the host rootfs to /host-rootfs and /dev/null to
# /etc/ld.so.preload: as root, it would create their placeholders in the
# / and the /etc of the host.
if [ `id -u` -eq 0 ]; then
    exit 125;
fi

# Termux preloads libtermux-exec in every program, PRoot included: the
# empty program below then runs as an empty shell script, it never
# reaches the command given to -q.
unset LD_PRELOAD

# The multi-call binary of uutils (the coreutils of Ubuntu 26.04) refuses
# to run as a utility /proc/self/exe doesn't name, and PRoot reports the
# guest program there: prefer the GNU utilities installed next to it.
gnu() {
    if [ -n "$(which gnu$1 2>/dev/null)" ]; then echo gnu$1; else echo $1; fi
}
TRUE=$(gnu true)
FALSE=$(gnu false)
ECHO=$(gnu echo)

TMP=${TMPDIR:?}/$(mcookie)
TMP2=${TMPDIR:?}/$(mcookie)

rm -f ${TMP}
touch ${TMP}
chmod +x ${TMP}

# Valgrind prepends "/bin/sh" in front of foreign binaries and uses
# LD_PRELOAD.
if $(echo ${PROOT} | grep -q valgrind); then
    ENV=$(which env)
    PROOT="env PROOT_FORCE_FOREIGN_BINARY=1 ${PROOT}"
    COMMAND1="-E LD_PRELOAD=.* -0 /bin/sh /bin/sh ${TMP}"
    TEST1="-- -U LD_LIBRARY_PATH -E LD_PRELOAD=.* -0 env ${ENV} LD_LIBRARY_PATH=test1 ${TMP}"
    TEST2="-- -E LD_PRELOAD=.* -E LD_LIBRARY_PATH=test2 -0 /bin/sh /bin/sh ${TMP}"
    TEST3="-- -E LD_PRELOAD=.* -E LD_LIBRARY_PATH=test2 -0 env ${ENV} LD_LIBRARY_PATH=test1 ${TMP}"
    TEST4="-- -U LD_LIBRARY_PATH -E LD_PRELOAD=.* -0 env ${ENV} LD_TRACE_LOADED_OBJECTS=1 ${TMP}"
    TEST5="-- -E LD_PRELOAD= -E LD_LIBRARY_PATH=test5 -0 sh /bin/sh -c ${TMP}"
    TEST52="-- -E LD_PRELOAD= -E LD_LIBRARY_PATH=test5 -0 sh /bin/sh -c sh -c ${TMP}"
    TEST6="-- -E LD_PRELOAD= -E LD_LIBRARY_PATH=test5 -0 env ${ENV} LD_LIBRARY_PATH=test6 ${TMP}"
    COMMAND2="-E LD_PRELOAD=.* -0 ${TMP} ${TMP} ${TMP2}"
else
    COMMAND1="-0 ${TMP} ${TMP}"
    TEST1="-- -E LD_LIBRARY_PATH=test1 ${COMMAND1}"
    TEST2="-- -E LD_LIBRARY_PATH=test2 ${COMMAND1}"
    TEST3="${TEST1}"
    # In the order of the environment, which differs on Termux.
    TEST4="-- (-E LD_TRACE_LOADED_OBJECTS=1 -E LD_LIBRARY_PATH=.+|-E LD_LIBRARY_PATH=.+ -E LD_TRACE_LOADED_OBJECTS=1) ${COMMAND1}"
    TEST5="-- -E LD_LIBRARY_PATH=test5 ${COMMAND1}"
    TEST52=${TEST5}
    TEST6="-- -E LD_LIBRARY_PATH=test6 ${COMMAND1}"
    COMMAND2="-0 ${TMP} ${TMP} ${TMP2}"
fi

  ${PROOT} -q ${TRUE} ${TMP}
! ${PROOT} -q ${FALSE} ${TMP}
[ $? -eq 0 ]

  (cd /; ${PROOT} -q ./$(which ${TRUE}) ${TMP})
! (cd /; ${PROOT} -q ./$(which ${FALSE}) ${TMP})
[ $? -eq 0 ]

HOST_LD_LIBRARY_PATH=$(${PROOT} -q "${ECHO} --" env | grep LD_LIBRARY_PATH)
test ! -z "${HOST_LD_LIBRARY_PATH}"

unset LD_LIBRARY_PATH
${PROOT} -q "${ECHO} --" ${TMP} | grep -- "^-- -U LD_LIBRARY_PATH ${COMMAND1}$"
${PROOT} -q "${ECHO} --" env LD_LIBRARY_PATH=test1 ${TMP} | grep -- "^${TEST1}$"
env LD_LIBRARY_PATH=test2 ${PROOT} -q "${ECHO} --" ${TMP} | grep -- "^${TEST2}$"

env LD_LIBRARY_PATH=test2 ${PROOT} -q "${ECHO} --" env LD_LIBRARY_PATH=test1 ${TMP} | grep -- "^${TEST3}$"

${PROOT} -q "${ECHO} --" env LD_TRACE_LOADED_OBJECTS=1 ${TMP} | grep -E -- "^${TEST4}$"

env LD_LIBRARY_PATH=test5 ${PROOT} -q "${ECHO} --" sh -c ${TMP} | grep -- "^${TEST5}$"
env LD_LIBRARY_PATH=test5 ${PROOT} -q "${ECHO} --" sh -c "sh -c ${TMP}" | grep -- "^${TEST52}$"
env LD_LIBRARY_PATH=test5 ${PROOT} -q "${ECHO} --" env LD_LIBRARY_PATH=test6 ${TMP} | grep -- "^${TEST6}$"

rm -f ${TMP2}
echo "#!${TMP}" > ${TMP2}
chmod +x ${TMP2}
${PROOT} -q "${ECHO} --" ${TMP2} | grep -- "^-- -U LD_LIBRARY_PATH ${COMMAND2}$"

rm -fr ${TMP} ${TMP2}
