if [ -z "$(which mcookie)" ] || [ -z "$(which stat)" ] || [ -z "$(which ln)" ]; then
    exit 125;
fi

# The link count link2symlink reports for a faked hard link has to be the
# same whether it is asked for with stat(2) or with statx(2): the latter
# is what any recent coreutils, libuv, ... use, and its result was
# dropped unless the extension told PRoot the buffer was updated -- every
# faked hard link looked like a file with a single link.

DIR=/tmp/$(mcookie).l2s
mkdir "${DIR}"
echo content > "${DIR}/original"

RESULT=$(${PROOT} -l sh -c "ln ${DIR}/original ${DIR}/link && stat -c %h ${DIR}/link")

rm -rf "${DIR}"

if [ "${RESULT}" != "2" ]; then
    exit 1
fi

exit 0
