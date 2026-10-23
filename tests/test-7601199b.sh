if [ ! -x /bin/sh ] || [ -z `which grep` ]; then
    exit 125;
fi

# Android has no /tmp before version 15.
${PROOT} -w /dev /bin/sh -c 'echo $PWD' | grep '^/dev$'
