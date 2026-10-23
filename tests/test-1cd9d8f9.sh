if ! `which pwd` -P || [ -z `which grep` ] ; then
    exit 125;
fi

# Android has no /tmp before version 15.
${PROOT} -w /dev pwd -P | grep '^/dev$'
