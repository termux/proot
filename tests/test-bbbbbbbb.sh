if [ -z `which mcookie` ] || [ -z `which rm` ] || [ -z `which ln` ]; then
    exit 125;
fi

DONT_EXIST=$(mcookie)
TMP1=$(mcookie)
TMP2=$(mcookie)

rm -f ${TMPDIR:?}/${DONT_EXIST}
${PROOT} ln -sf /${DONT_EXIST} ${TMPDIR:?}/
${PROOT} ln -sf /${DONT_EXIST} ${TMPDIR:?}/

rm -f ${TMPDIR:?}/${DONT_EXIST}
  ${PROOT} ln -sf /etc/fstab/${DONT_EXIST} ${TMPDIR:?}/
! ${PROOT} ln -sf /etc/fstab/${DONT_EXIST} ${TMPDIR:?}/

rm -f ${TMPDIR:?}/${DONT_EXIST}
rm -f ${TMPDIR:?}/${TMP1} ${TMPDIR:?}/${TMP2}
touch ${TMPDIR:?}/${TMP2}
ln -sf ${TMPDIR:?}/${DONT_EXIST} ${TMPDIR:?}/${TMP1}
! ${PROOT} ln ${TMPDIR:?}/${TMP2} ${TMPDIR:?}/${TMP1}

rm -f ${TMPDIR:?}/${TMP1} ${TMPDIR:?}/${TMP2}
rm -f ${TMPDIR:?}/${DONT_EXIST}
