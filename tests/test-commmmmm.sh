if [ -z `which mcookie` ] || [ -z `which cat` ] || [ -z `which grep` ] || [ -z `which chmod` ] || [ -z `which cut` ] || [ -z `which rm` ] || [ -z `which ln` ] || [ -z `which env` ]; then
    exit 125;
fi

TMP=$(mcookie)
TMP2=$(echo ${TMP} | cut -b 1-15)
TMP3=$(mcookie)
TMP4=$(echo ${TMP3} | cut -b 1-15)

${PROOT} cat /proc/self/comm          | grep cat
${PROOT} $(which cat) /proc/self/comm | grep cat

echo '#!/bin/sh' > ${TMPDIR:?}/${TMP}
chmod +x ${TMPDIR:?}/${TMP}

# TODO: (cd ${TMPDIR:?}; ${PROOT} env LD_SHOW_AUXV=1 ./${TMP}) | grep ^AT_EXECFN:[[:space:]]*./${TMP}$

echo 'cat /proc/$$/comm' >> ${TMPDIR:?}/${TMP}

${PROOT} ${TMPDIR:?}/${TMP} | grep ^${TMP2}$

ln -s ${TMPDIR:?}/${TMP} ${TMPDIR:?}/${TMP3}
${PROOT} ${TMPDIR:?}/${TMP3} /proc/self/comm | grep ^${TMP4}$

rm -f ${TMPDIR:?}/${TMP} ${TMPDIR:?}/${TMP3}
