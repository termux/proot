if [ -z `which mcookie` ] || [ -z `which mkdir` ] || [ -z `which bash` ] || [ -z `which grep` ] || [ -z `which rm` ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)

mkdir -p ${TMP}
cd ${TMP}

${PROOT} -b ${PWD}:/foo -w /foo bash -c 'pwd' | grep '^/foo$'

rm -fr ${TMP}
