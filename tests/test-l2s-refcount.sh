#!/bin/sh
# link2symlink emulation: refcount lifecycle, nlink faking, errno
# fidelity, and suffix reuse.  Runs against the host rootfs with
# busybox applets (multicall dispatch by explicit applet name survives
# proot's exec renaming).  PROOT_L2S_FORCE=1 forces the emulation even
# where the host filesystem supports real hard links.

BB=$(command -v busybox) || exit 125
[ -n "$PROOT" ] || exit 125
command -v mktemp > /dev/null || exit 125

TMP=$(mktemp -d) || exit 125
trap 'rm -rf "$TMP"' EXIT

run() {
    env PROOT_L2S_FORCE=1 ${PROOT} --link2symlink -w "$TMP" "$BB" sh -e -c "$1"
}

# 1. link + content + faked nlink on both names
run 'echo data > a
     busybox ln a b
     busybox cmp a b
     test "$(busybox stat -c %h a)" = 2
     test "$(busybox stat -c %h b)" = 2'

# 2. unlink one referent: nlink back to 1, content intact
run 'busybox rm b
     test "$(busybox stat -c %h a)" = 1
     test "$(busybox cat a)" = data'

# 3. unlink the last referent: payload is garbage-collected
run 'busybox rm a'
LEFT=$(ls -A "$TMP")
[ -z "$LEFT" ] || { echo "residue after last unlink: $LEFT"; exit 1; }

# 4. errno fidelity: missing source is ENOENT (not the old blanket
#    EPERM from raw -1 returns), directory source is EPERM
#    (if-guarded so `sh -e` harness runs survive the expected failures)
if ERR=$(run 'busybox ln missing t' 2>&1); then
    echo "ln of a missing source unexpectedly succeeded"; exit 1
fi
echo "$ERR" | grep -q "No such file" || { echo "want ENOENT, got: $ERR"; exit 1; }
if ERR=$(run 'busybox mkdir -p d; busybox ln d t2' 2>&1); then
    echo "ln of a directory unexpectedly succeeded"; exit 1
fi
echo "$ERR" | grep -qi "not permitted" || { echo "want EPERM, got: $ERR"; exit 1; }
rm -rf "$TMP"/d

# 5. suffix reuse: repeated create/link/rm must not accumulate chain
#    files (the old access(F_OK) scan leaked on dangling intermediates)
for i in 1 2 3; do
    run 'echo x > f; busybox ln f g; busybox rm f g'
done
LEFT=$(ls -A "$TMP" | grep '\.l2s\.' || true)
[ -z "$LEFT" ] || { echo "chain residue after loop: $LEFT"; exit 1; }

exit 0
