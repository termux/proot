#!/bin/sh
# PROOT_L2S_DIR payload relocation: the distilled libgit2/Nix repro.
# Without relocation, link(tmpd/A, repo/B) parks the real payload in
# tmpd, so `rm -rf tmpd` destroys it and repo/B dangles — exactly how
# Nix 2.26's tarball cache lost its HEAD under proot
# (GlassHaven/Haven discussion #536).  With PROOT_L2S_DIR the payload
# survives any user-directory deletion.

BB=$(command -v busybox) || exit 125
[ -n "$PROOT" ] || exit 125
command -v mktemp > /dev/null || exit 125

TMP=$(mktemp -d) || exit 125
L2S="$TMP/.l2s"
mkdir -p "$L2S"
trap 'rm -rf "$TMP"' EXIT

run() {
    env PROOT_L2S_FORCE=1 PROOT_L2S_DIR="$L2S" \
        ${PROOT} --link2symlink -w "$TMP" "$BB" sh -e -c "$1"
}

# 1. payload lands in the l2s dir, not the source dir
run 'busybox mkdir tmpd repo
     echo payload > tmpd/A
     busybox ln tmpd/A repo/B'
ls -A "$L2S" | grep -q '\.l2s\.A' || { echo "payload not in L2S dir"; ls -A "$L2S"; exit 1; }
ls -A "$TMP/tmpd" | grep -q '\.l2s\.' && { echo "chain leaked into source dir"; exit 1; }

# 2. THE repro: delete the source dir, surviving referent still reads
run 'busybox rm -rf tmpd
     test "$(busybox cat repo/B)" = payload
     test "$(busybox stat -c %h repo/B)" = 1'

# 3. last unlink garbage-collects the payload from the l2s dir
run 'busybox rm repo/B'
LEFT=$(ls -A "$L2S")
[ -z "$LEFT" ] || { echo "payload residue: $LEFT"; exit 1; }

# 4. ENOENT resilience: a deleted l2s dir is recreated on demand
rmdir "$L2S"
run 'echo x > p; busybox ln p q; busybox cmp p q'
[ -d "$L2S" ] || { echo "l2s dir not recreated"; exit 1; }

exit 0
