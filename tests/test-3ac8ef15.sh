if [ -z "$(which mcookie)" ] || [ -z "$(which sleep)" ] || [ -z "$(which head)" ]; then
    exit 125;
fi

# Companion to test-b3e7f2d8.sh, which only reproduces the EPIPE race on
# slow enough machines: here the writer is delayed on purpose, so the
# reader is guaranteed to be gone by the time the write happens.  The
# shadow read end must keep the pipe alive; without it the writer is
# killed by SIGPIPE and never creates the marker.

MARKER=${TMPDIR:?}/$(mcookie).marker
rm -f "${MARKER}"

${PROOT} sh -c "{ echo x; sleep 0.2; echo y; touch ${MARKER}; } | head -c 2 > /dev/null"

if [ ! -e "${MARKER}" ]; then
    exit 1
fi

rm -f "${MARKER}"
exit 0
