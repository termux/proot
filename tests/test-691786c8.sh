if [ ! -x /usr/bin/echo ] || [ -z `which mcookie` ] || [ -z `which chmod` ] || [ -z `which env` ] || [ -z `which rm` ]; then
    exit 125;
fi

TMP=${TMPDIR:?}/$(mcookie)

echo '#!/usr/bin/echo XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' > ${TMP}

chmod +x ${TMP}

RESULT=$(${PROOT} ${TMP})
EXPECTED=$(${TMP})

[ "${RESULT}" = "${EXPECTED}" ]

# The kernel reads at most BINPRM_BUF_SIZE bytes of the "#!" line and
# ignores the rest: 128 before Linux 5.1, 256 since then.  The lines below
# are longer than 128 bytes, so their results are compared with the
# kernel's rather than with what either size gives.

echo '#!//../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../usr/bin/echo XXXXXXXXX' > ${TMP}

RESULT=$(${PROOT} ${TMP})
EXPECTED=$(${TMP})

[ "${RESULT}" = "${EXPECTED}" ]

echo '#!/../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../usr/bin/echo XXXXXXXXX' > ${TMP}

RESULT=$(${PROOT} ${TMP} 2>/dev/null || echo failed)
EXPECTED=$(${TMP} 2>/dev/null || echo failed)

[ "${RESULT}" = "${EXPECTED}" ]

echo '#!                                                                                                                                                                                                        ' > ${TMP}

${PROOT} ${TMP}

echo '#!' > ${TMP}

${PROOT} ${TMP}

/usr/bin/echo "#!${TMP}" > ${TMP}

env LANG=C ${PROOT} ${TMP} 2>&1 | grep 'Too many levels of symbolic links'
[ $? -eq 0 ]

rm -f ${TMP}
