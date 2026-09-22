if [ -z "$(which mcookie)" ] || [ -z "$(which ln)" ] || [ ! -x ${ROOTFS}/bin/open_nofollow ]; then
    exit 125;
fi

# Same as test-7fa2c1d4, for a descriptor opened without following its
# last component: open(O_NOFOLLOW) and open(O_PATH | O_NOFOLLOW).  A faked
# hard link is a regular file to the tracee, so such an open succeeds and
# is named after the link, as with a real hard link.  link2symlink
# dereferences the link itself in that case -- the canonicalization was
# asked not to -- and used to leave the descriptor named after the file it
# is stored as in the l2s directory.

DIR=/tmp/$(mcookie).l2s
mkdir "${DIR}"
echo content > "${DIR}/original"

${PROOT} -l ln "${DIR}/original" "${DIR}/link"

RESULT=$(${PROOT} -l -b /proc ${ROOTFS}/bin/open_nofollow "${DIR}/link")
RESULT2=$(${PROOT} -l -b /proc ${ROOTFS}/bin/open_nofollow "${DIR}/link" path)

rm -rf "${DIR}"

if [ "${RESULT}" != "${DIR}/link" ] || [ "${RESULT2}" != "${DIR}/link" ]; then
    exit 1
fi

exit 0
