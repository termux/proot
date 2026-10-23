if [ ! -x ${ROOTFS}/bin/true ] || [ -z `which id` ] || [ -z `which mcookie` ] || [ -z `which ln` ] || [ -z `which rm` ]; then
    exit 125;
fi

if [ `id -u` -eq 0 ]; then
    exit 125;
fi

DONT_EXIST=/$(mcookie)

${PROOT} -r ${ROOTFS} true

! ${PROOT} ${DONT_EXIST} true
[ $? -eq 0 ]

${PROOT} -r ${ROOTFS} true
${PROOT} -r /etc -r ${ROOTFS} true

! ${PROOT} -r ${ROOTFS} -r ${DONT_EXIST} true
[ $? -eq 0 ]

! ${PROOT} -r ${DONT_EXIST} ${ROOTFS} true
[ $? -eq 0 ]

! ${PROOT} ${ROOTFS} -r ${ROOTFS} true
[ $? -eq 0 ]

! ${PROOT} -v
[ $? -eq 0 ]

${PROOT} -b /bin/true:${DONT_EXIST} ${DONT_EXIST}

! ${PROOT} -r / -b /etc:/ true
[ $? -eq 0 ]

! ${PROOT} -b /etc:/ true
[ $? -eq 0 ]

${PROOT} -b /etc:/ -r / true

TMP1=${TMPDIR:?}/$(mcookie)
TMP2=${TMPDIR:?}/$(mcookie)

echo "${TMP1}" > ${TMP1}
echo "${TMP2}" > ${TMP2}

REGULAR=${TMPDIR:?}/$(mcookie)
SYMLINK_TO_REGULAR=${TMPDIR:?}/$(mcookie)
ln -s ${REGULAR} ${SYMLINK_TO_REGULAR}

${PROOT} -v -1 -b ${TMP1}:${REGULAR} -b ${TMP2}:${SYMLINK_TO_REGULAR} cat ${REGULAR} | grep "^${TMP2}$"
${PROOT} -v -1 -b ${TMP2}:${SYMLINK_TO_REGULAR} -b ${TMP1}:${REGULAR} cat ${REGULAR} | grep "^${TMP1}$"

${PROOT} -v -1 -b ${TMP1}:${REGULAR} -b ${TMP2}:${SYMLINK_TO_REGULAR}! cat ${REGULAR} | grep "^${TMP1}$"
${PROOT} -v -1 -b ${TMP1}:${REGULAR} -b ${TMP2}:${SYMLINK_TO_REGULAR}! cat ${SYMLINK_TO_REGULAR} | grep "^${TMP2}$"

${PROOT} -v -1 -b ${TMP1}:${REGULAR}! -b ${TMP2}:${SYMLINK_TO_REGULAR}! cat ${REGULAR} | grep "^${TMP1}$"
${PROOT} -v -1 -b ${TMP1}:${REGULAR}! -b ${TMP2}:${SYMLINK_TO_REGULAR}! cat ${SYMLINK_TO_REGULAR} | grep "^${TMP2}$"

${PROOT} -v -1 -b ${TMP1}:${REGULAR} -b ${TMP2}:${SYMLINK_TO_REGULAR} cat ${SYMLINK_TO_REGULAR} | grep "^${TMP2}$"
${PROOT} -v -1 -b ${TMP2}:${SYMLINK_TO_REGULAR} -b ${TMP1}:${REGULAR} cat ${SYMLINK_TO_REGULAR} | grep "^${TMP1}$"

rm -fr ${TMP1} ${TMP2} ${REGULAR} ${SYMLINK_TO_REGULAR}
