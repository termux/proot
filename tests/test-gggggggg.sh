if [ -z `which mcookie` ] || [ -z `which env` ] || [ -z `which mkdir` ] || [ -z `which rm` ] || [ ! -x ${ROOTFS}/bin/readdir ]; then
    exit 125;
fi

# The glue lies among the temporary files of PRoot, under the guest path
# of the binding: only a directory of this test is bound there, nothing
# of the system (see test-a5f1d3c9.sh).
TMP=${TMPDIR:?}/$(mcookie)
BOUND=${TMPDIR:?}/$(mcookie)
mkdir ${TMP} ${BOUND}
touch ${BOUND}/file

! env PROOT_DONT_POLLUTE_ROOTFS=1 ${PROOT} -b ${BOUND}:${TMP}/dont/create ${ROOTFS}/bin/readdir ${TMP} | grep -w dont
[ $? -eq 0 ]

env PROOT_DONT_POLLUTE_ROOTFS=1 ${PROOT} -b ${BOUND}:${TMP}/dont/create test -e ${TMP}/dont

${PROOT} -b ${BOUND}:${TMP}/dont/create test -e ${TMP}/dont

! test -e ${TMP}/dont
[ $? -eq 0 ]

chmod +rx -R ${TMP}
rm -fr ${TMP} ${BOUND}
