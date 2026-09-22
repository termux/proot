if [ -z "$(which mcookie)" ] || [ -z "$(which ln)" ] || [ -z "$(which sh)" ] || [ ! -x ${ROOTFS}/bin/puts_proc_self_exe ]; then
    exit 125;
fi

# A program executed through a hard link reports that link through
# /proc/self/exe, whatever symbolic links lead to it.  link2symlink used to
# report the file it hides in the l2s directory instead, which broke
# programs that validate their executable name: the multi-call coreutils
# of Ubuntu -- "/usr/bin/uname -> ../lib/cargo/bin/coreutils/uname", a hard
# link to "/usr/bin/coreutils" -- refused to run once dpkg had installed
# them under link2symlink:
#
#     Security violation: Requested utility `uname` does not match
#     executable name: /.l2s/.l2s.coreutils.dpkg-new0001.0116
#
# The link has to be faked by PRoot itself: a real hard link created on the
# host would pass this test without link2symlink doing anything.

DIR=/tmp/$(mcookie).l2s
mkdir "${DIR}" "${DIR}/bin" "${DIR}/lib"
cp ${ROOTFS}/bin/puts_proc_self_exe "${DIR}/lib/original"

${PROOT} -l ln "${DIR}/lib/original" "${DIR}/lib/link"
ln -s ../lib/link "${DIR}/bin/symlink"

# Launched by PRoot, which looks up the program before the tracee starts.
RESULT1=$(${PROOT} -l -b /proc "${DIR}/lib/link")
RESULT2=$(${PROOT} -l -b /proc "${DIR}/bin/symlink")

# Executed by the tracee.
RESULT3=$(${PROOT} -l -b /proc sh -c "${DIR}/lib/link")
RESULT4=$(${PROOT} -l -b /proc sh -c "${DIR}/bin/symlink")
RESULT5=$(${PROOT} -l -b /proc sh -c "${DIR}/lib/original")

rm -rf "${DIR}"

if [ "${RESULT1}" != "${DIR}/lib/link" ] \
   || [ "${RESULT2}" != "${DIR}/lib/link" ] \
   || [ "${RESULT3}" != "${DIR}/lib/link" ] \
   || [ "${RESULT4}" != "${DIR}/lib/link" ] \
   || [ "${RESULT5}" != "${DIR}/lib/original" ]; then
    exit 1
fi

exit 0
