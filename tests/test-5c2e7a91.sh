if [ -z "$(which mcookie)" ] || [ -z "$(which seq)" ] || [ -z "$(which xargs)" ] || [ -z "$(which ln)" ] || [ -z "$(which cat)" ]; then
    exit 125;
fi

# The first hard link link2symlink fakes for a file moves it to a final
# file named after an intermediate, "<PREFIX><name>" plus the first
# four-digit suffix that is free.  Once they were all taken it went on
# with the last one anyway: the file was moved onto that suffix's final
# file, replacing whatever was there, then creating the intermediate
# failed -- reported as EPERM -- and nothing moved the file back.  A
# dangling intermediate counted as free and ended the same way, and a
# final file left without its intermediate was silently replaced.
#
# The link has to either fail or succeed; the file has to stay.

# The intermediates have to be created next to the files.
unset PROOT_L2S_DIR

DIR=/tmp/$(mcookie).l2s
mkdir "${DIR}"

# Every suffix taken: the link is refused with EMLINK, the file untouched.
mkdir "${DIR}/full"
echo content > "${DIR}/full/original"
seq -f "${DIR}/full/.l2s.original%04g" 1 9999 | xargs touch
if MESSAGE=$(LC_ALL=C ${PROOT} -l ln "${DIR}/full/original" "${DIR}/full/link" 2>&1); then
    FULL=linked
else
    FULL=refused
fi
FULL_CONTENT=$(cat "${DIR}/full/original" 2>&1)

# A dangling intermediate is taken: the next suffix is used instead.
mkdir "${DIR}/dangling"
echo content > "${DIR}/dangling/original"
ln -s "${DIR}/dangling/.l2s.original0001.0002" "${DIR}/dangling/.l2s.original0001"
DANGLING=$(${PROOT} -l sh -c "ln ${DIR}/dangling/original ${DIR}/dangling/link && cat ${DIR}/dangling/original ${DIR}/dangling/link" 2>&1)

# A final file left without its intermediate is not replaced.
mkdir "${DIR}/stale"
echo content > "${DIR}/stale/original"
echo stale > "${DIR}/stale/.l2s.original0001.0002"
STALE=$(${PROOT} -l sh -c "ln ${DIR}/stale/original ${DIR}/stale/link && cat ${DIR}/stale/original ${DIR}/stale/link" 2>&1)
STALE_KEPT=$(cat "${DIR}/stale/.l2s.original0001.0002" 2>&1)

rm -rf "${DIR}"

if [ "${FULL}" != "refused" ] || [ "${FULL_CONTENT}" != "content" ]; then
    exit 1
fi

case "${MESSAGE}" in
    *"Too many links"*) ;;
    *) exit 1 ;;
esac

if [ "${DANGLING}" != "$(printf 'content\ncontent')" ]; then
    exit 1
fi

if [ "${STALE}" != "$(printf 'content\ncontent')" ] || [ "${STALE_KEPT}" != "stale" ]; then
    exit 1
fi

exit 0
