if [ -z `which mcookie` ] || [ -z `which grep` ] || [ -z `which rm` ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)
echo "OK" > ${TMP}

${PROOT} -b ${TMP}:/etc/fstab -b /dev/null -b /etc cat /etc/fstab | grep ^OK$

rm ${TMP}
