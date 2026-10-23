if [ -z `which mcookie` ] || [ -z `which rm` ] || [ -z `which ln` ] || [ -z `which realpath` ] || [ -z `which mkdir` ] || [ -z `which rmdir` ]; then
    exit 125;
fi

CHECK1=$(realpath -e /proc/self/exe)
CHECK2=$(realpath /proc/self/exe)

if [ "${CHECK1}" != "${CHECK2}" ]; then
    exit 125;
fi

TMP="${TMPDIR:?}/$(mcookie)"
TMP2="${TMPDIR:?}/$(mcookie)"

RMDIR=$(realpath -e $(which rmdir))
MKDIR=$(realpath -e $(which mkdir))

export LANG=C

# Symlinks to paths of this test, so that nothing else is at stake if
# PRoot ever followed them.
mkdir ${TMP}.dir
ln -s ${TMP}.dir ${TMP}
! ${RMDIR} ${TMP} > ${TMP}.ref 2>&1
! ${PROOT} -v -1 ${RMDIR} ${TMP} > ${TMP}.res 2>&1
cmp ${TMP}.ref ${TMP}.res

ln -s ${TMP2}.missing ${TMP2}
! ${MKDIR} ${TMP2} > ${TMP2}.ref 2>&1
! ${PROOT} -v -1 ${MKDIR} ${TMP2} > ${TMP2}.res 2>&1
cmp ${TMP2}.ref ${TMP2}.res

rm -f ${TMP}
rm -f ${TMP}.ref
rm -f ${TMP}.res
rmdir ${TMP}.dir

rm -f ${TMP2}
rm -f ${TMP2}.ref
rm -f ${TMP2}.res
