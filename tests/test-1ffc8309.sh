if [ -z `which mcookie` ] || [ -z `which mkdir` ] || [ -z `which env` ] || [ -z `which uname` ] || [ -z `which rm` ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)

mkdir ${TMP}

env PROOT_FORCE_KOMPAT=1 ${PROOT} -k $(uname -r) rm -r ${TMP}
