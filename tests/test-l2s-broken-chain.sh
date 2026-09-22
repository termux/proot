#!/bin/sh
# Broken-chain fail-soft (GlassHaven/Haven#329): a stub whose
# intermediate/payload were destroyed behind proot's back must remain
# visible (lstat) and removable, and unlinking the debris must not
# error — otherwise `rm -rf` aborts partway.

BB=$(command -v busybox) || exit 125
[ -n "$PROOT" ] || exit 125
command -v mktemp > /dev/null || exit 125

TMP=$(mktemp -d) || exit 125
trap 'rm -rf "$TMP"' EXIT

run() {
    env PROOT_L2S_FORCE=1 ${PROOT} --link2symlink -w "$TMP" "$BB" sh -e -c "$1"
}

# Build a chain, then break it host-side (delete intermediate+payload).
run 'echo data > a; busybox ln a b'
rm -f "$TMP"/.l2s.a*

# The dangling stubs must still be visible and removable in the guest.
run 'test -h a
     test -h b
     busybox rm a b'

LEFT=$(ls -A "$TMP")
[ -z "$LEFT" ] || { echo "residue: $LEFT"; exit 1; }

exit 0
