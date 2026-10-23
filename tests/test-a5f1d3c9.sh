if [ -z "$(which mcookie)" ] || [ -z "$(which env)" ] || [ -z "$(which find)" ]; then
    exit 125;
fi

# When the program couldn't be executed, the child PRoot forks for it
# went back to main() and exited through the talloc destructors, which
# remove the glue and the placeholders of the bindings.  This child is
# traced already, so its syscalls were translated: the removal of the
# glue followed the binding it was made for and deleted the content of
# the host directory bound there, then this directory itself -- /usr/bin
# for "-b /bin:..." as root.  Its sanity check, that the directory being
# emptied lies in the temporary directory of PRoot, passed whenever the
# guest path of the binding did: /proc/self/cwd tells the guest path.
#
# Only files of this test are at stake: the bound directory is its own,
# so is the temporary directory of PRoot, and the program is a script
# whose interpreter doesn't exist.

DIR=${TMPDIR:?}/$(mcookie)
mkdir -p "${DIR}/bound/sub" "${DIR}/tmp/guest"
echo content > "${DIR}/bound/file"
echo content > "${DIR}/bound/sub/file"
printf '#!%s/nonexistent\n' "${DIR}" > "${DIR}/script"
chmod +x "${DIR}/script"

# With the glue in the temporary directory, then with placeholders.
for POLLUTE in PROOT_DONT_POLLUTE_ROOTFS=1 ""; do
    ! env ${POLLUTE} PROOT_TMP_DIR="${DIR}/tmp" ${PROOT} \
        -b "${DIR}/bound:${DIR}/tmp/guest/missing/bound" "${DIR}/script"
done

RESULT=$(cd "${DIR}" && find bound tmp | sort)

rm -rf "${DIR}"

EXPECTED='bound
bound/file
bound/sub
bound/sub/file
tmp
tmp/guest'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
