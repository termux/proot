if [ -z `which mknod` ] || [ -z `which mcookie` ] || [ `id -u` -eq 0 ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)

! ${PROOT} mknod ${TMP} b 1 1
[ $? -eq 0 ]

! ${PROOT} -i 123:456 mknod ${TMP} b 1 1
[ $? -eq 0 ]

${PROOT} -0 mknod ${TMP} b 1 1

rm -f ${TMP}
