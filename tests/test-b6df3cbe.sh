if [ -z `which mcookie` ] ||  [ -z `which cat` ] || [ -z `which tr` ] || [ -z `which grep` ] || [ -z `which grep` ] || [ -z `which chmod` ]; then
    exit 125;
fi

TMP=$(mcookie)

cat > ${TMPDIR:?}/${TMP} <<EOF
#!/bin/sh

cat /proc/\$$/cmdline
EOF

chmod +x ${TMPDIR:?}/${TMP}
(cd ${TMPDIR:?}; ${PROOT} sh -c "./${TMP}") | tr '\000' ' ' | grep "^/bin/sh ./${TMP} $"

rm ${TMPDIR:?}/${TMP}
