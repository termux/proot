if [ -z `which mcookie` ] || [ -z `which mkdir` ] || [ -z `which rm` ] || [ ! -x ${ROOTFS}/bin/pwd ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)
mkdir ${TMP}
cd ${TMP}
${PROOT} sh -c "cd ..; rm -r ${TMP}; mkdir ${TMP}; cd ${TMP}; ${ROOTFS}/bin/pwd"

rm -fr ${TMP}
