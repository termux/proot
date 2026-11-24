if [ -z "$(which sh)" ] || [ -z "$(which sleep)" ]; then
    exit 125;
fi

# PRoot exits with the status of the last tracee that exited, so the
# death of the program it was asked to run by a signal was left out:
# PRoot exited with the status of the last tracee that exited before --
# the 0 of the children Android's crash handler runs, after a crash --
# or with 255 when there was none.  This signal is reported the way
# shells do now.  The deaths of the other tracees are still left out,
# the ones --kill-on-exit kills or a "kill $!" of a job for instance.

set +e
${PROOT} sh -c 'kill -SEGV $$' 2>/dev/null
ALONE=$?
${PROOT} sh -c '(exit 0); (exit 5); kill -SEGV $$' 2>/dev/null
AFTER=$?
${PROOT} sh -c 'sh -c "kill -KILL \$\$"; exit 4' 2>/dev/null
CHILD=$?
${PROOT} sh -c 'sleep 2 & sleep 1; kill $!' 2>/dev/null
JOB=$?
${PROOT} sh -c 'exit 7' 2>/dev/null
EXITED=$?
${PROOT} --kill-on-exit sh -c 'sleep 100 & exit 3' 2>/dev/null
KILL_ON_EXIT=$?
${PROOT} --kill-on-exit sh -c 'sleep 100 & kill -TERM $$' 2>/dev/null
KILL_ON_EXIT_SIGNALED=$?
set -e

RESULT="${ALONE} ${AFTER} ${CHILD} ${JOB} ${EXITED} ${KILL_ON_EXIT} ${KILL_ON_EXIT_SIGNALED}"
EXPECTED="139 139 4 0 7 3 143"

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
