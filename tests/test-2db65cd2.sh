if [ ! -x  ${ROOTFS}/bin/true ] || [ -z `which gdb` ]; then
    exit 125;
fi

TMP1=${TMPDIR:?}/$(mcookie)
TMP2=${TMPDIR:?}/$(mcookie)
TMP3=${TMPDIR:?}/$(mcookie)
TMP4=${TMPDIR:?}/$(mcookie)
TMP5=${TMPDIR:?}/$(mcookie)

cat > ${TMP5} <<EOF
break main
run
cont
EOF

COMMAND="gdb ${ROOTFS}/bin/true -batch -n -x ${TMP5}"

${COMMAND} > ${TMP1}
! grep -v 'process' ${TMP1} > ${TMP2}

${PROOT} ${COMMAND} > ${TMP4}
! grep -v 'process' ${TMP4} > ${TMP3}
! grep -v '^proot warning: ' ${TMP3} > ${TMP4}

cmp ${TMP2} ${TMP4}

rm -f ${TMP1} ${TMP2} ${TMP3} ${TMP4} ${TMP5}
