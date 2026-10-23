if [ -z `which mcookie` ] || [ -z `which grep` ] || [ -z `which rm` ]; then
    exit 125;
fi

# Without this file, PRoot would create a placeholder for the binding in
# the /etc of the host whenever it can write there.
if [ ! -e /etc/fstab ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)
echo "OK" > ${TMP}

${PROOT} -b ${TMP}:/etc/fstab -b /dev/null -b /etc cat /etc/fstab | grep ^OK$

rm ${TMP}
