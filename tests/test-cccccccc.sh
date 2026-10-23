if [ -z `which mcookie` ] || [ -z `which rmdir` ] || [ -z `which mkdir` ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)
mkdir ${TMP}

! ${PROOT} rmdir ${TMP}/.
[ $? -eq 0 ]

! ${PROOT} rmdir ${TMP}/./
[ $? -eq 0 ]

${PROOT} rmdir ${TMP}
