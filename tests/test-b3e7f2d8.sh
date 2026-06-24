if [ -z "$(which bash)" ] || [ -z "$(which mcookie)" ] || [ ! -e /proc/self/fd/0 ]; then
    exit 125;
fi

# Regression test: echo <(echo a) must not produce "Broken pipe" under
# -b /proc/self/fd:/dev/fd.  ptrace serialisation causes the parent to
# close the pipe read end before the child writes; proot's shadow pipe
# mechanism keeps the read end alive so the write does not get EPIPE.

ERR=/tmp/$(mcookie).err
${PROOT} -b /proc/self/fd:/dev/fd \
    bash -c 'echo <(echo a)' 2>"${ERR}"
STATUS=$?

if grep -q "Broken pipe" "${ERR}"; then
    rm -f "${ERR}"
    exit 1
fi
rm -f "${ERR}"

exit ${STATUS}
