#!/bin/sh
# PROOT_L2S_DIR as a GUEST path with a real (non-/) rootfs — the Haven
# configuration.  Chain symlink content must be guest-absolute so the
# in-guest canonicalizer can deref stubs: with host-absolute content,
# open() through a stub fails ENOENT on Android even though the
# extension's host-side walks succeed (the gap the earlier rootfs=/
# tests could not see, since host and guest forms coincide there).

BB=$(command -v busybox) || exit 125
[ -n "$PROOT" ] || exit 125
command -v mktemp > /dev/null || exit 125
# busybox must be static to run inside an empty rootfs
$BB --help > /dev/null 2>&1 || exit 125
if command -v ldd > /dev/null 2>&1; then
    ldd "$BB" > /dev/null 2>&1 && exit 125
fi

TMP=$(mktemp -d) || exit 125
trap 'rm -rf "$TMP"' EXIT

# Minimal rootfs: static busybox + the dirs the test touches.
mkdir -p "$TMP/rootfs/bin" "$TMP/rootfs/root" "$TMP/rootfs/.l2s"
cp "$BB" "$TMP/rootfs/bin/busybox"
ln -s busybox "$TMP/rootfs/bin/sh"

run() {
    env PROOT_L2S_FORCE=1 PROOT_L2S_DIR=/.l2s \
        ${PROOT} --link2symlink -r "$TMP/rootfs" -w /root /bin/sh -e -c "$1"
}

# 1. link works; payload lands in /.l2s; chain content is guest-form
run 'busybox mkdir tmpd repo
     echo payload > tmpd/A
     busybox ln tmpd/A repo/B'
ls -A "$TMP/rootfs/.l2s" | grep -q '\.l2s\.A' || { echo "payload not in rootfs/.l2s"; exit 1; }
TARGET=$(readlink "$TMP/rootfs/root/repo/B")
case "$TARGET" in
    /.l2s/*) ;;
    *) echo "stub content not guest-form: $TARGET"; exit 1;;
esac

# 2. reading THROUGH the stub inside the guest (the on-device failure)
run 'test "$(busybox cat repo/B)" = payload
     test "$(busybox stat -c %h repo/B)" = 2'

# 3. the durability repro: delete the source dir, referent survives
run 'busybox rm -rf tmpd
     test "$(busybox cat repo/B)" = payload
     test "$(busybox stat -c %h repo/B)" = 1'

# 4. last unlink garbage-collects the payload
run 'busybox rm repo/B'
LEFT=$(ls -A "$TMP/rootfs/.l2s")
[ -z "$LEFT" ] || { echo "payload residue: $LEFT"; exit 1; }

exit 0
