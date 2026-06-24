if [ -z `which mcookie` ] || [ -z `which cat` ] || [ -z `which grep` ] || [ -z `which sh` ] || [ ! -e /proc/self/fd/0 ]; then
    exit 125;
fi

# Regression test for: /dev/fd/N broken when -b /proc/self/fd:/dev/fd is used.
# After commit 898b4a8 (dereference=false for dir sources), the binding is
# registered at the literal guest path /dev/fd.  Accessing /dev/fd/N then
# passes proc_base="/proc/self/fd" to readlink_proc; atoi("self/fd")==0 caused
# DEFAULT to be returned, falling through to readlink(2) in proot's own
# namespace → ENOENT.  The fix normalises /proc/self/... to /proc/<pid>/...
# inside readlink_proc so DONT_CANONICALIZE is correctly returned.

TMP=/tmp/$(mcookie)
echo "hello" > ${TMP}

# Bind /proc/self/fd explicitly to /dev/fd (common in proot-distro setups).
# Open the file on fd 3 via a redirect and read it back through /dev/fd/3.
${PROOT} -b /proc/self/fd:/dev/fd \
    sh -c 'cat /dev/fd/3 3</dev/stdin' < ${TMP} | grep ^hello$

rm -f ${TMP}
