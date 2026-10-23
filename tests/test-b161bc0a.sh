if [ -z `which pwd` ] || [ -z `which grep` ] || [ -z `which mcookie` ]; then
    exit 125;
fi

# The guest path doesn't exist, so PRoot creates a placeholder for the
# binding while it runs: in the temporary directory of the suite rather
# than in the /tmp of the host.
TMP=${TMPDIR:?}/$(mcookie)

${PROOT} -w ${TMP} -m /etc:${TMP} pwd | grep "^${TMP}$"

