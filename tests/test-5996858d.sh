if [ -z `which uname` ] || [ -z `which grep` ] || [ -z `which domainname` ] || [ -z `which hostname` ]|| [ -z `which env` ] || [ -z `which true` ] || [ -z `which id` ]; then
    exit 125;
fi

UTSNAME="\\sysname\\nodename\\$(uname -r)\\version\\machine\\domainname\\0\\"

${PROOT} -k ${UTSNAME} uname -s | grep ^sysname$
${PROOT} -k ${UTSNAME} uname -n | grep ^nodename$
${PROOT} -k ${UTSNAME} uname -v | grep ^version$
${PROOT} -k ${UTSNAME} uname -m | grep ^machine$
${PROOT} -k ${UTSNAME} domainname | grep ^domainname$
# Recent versions of glibc print "0x0" where older ones print "0".
${PROOT} -k ${UTSNAME} env LD_SHOW_AUXV=1 true | grep -E '^AT_HWCAP:[[:space:]]*(0x)?0?$'

# PRoot lets the kernel run sethostname(2) and setdomainname(2), -0 only
# turns their refusal into a success before the names are faked: as root,
# these would rename the host.
if [ "$(id -u)" -eq 0 ]; then
    exit 0
fi

${PROOT} -0 -k ${UTSNAME} sh -c 'domainname domainname2; domainname' | grep ^domainname2$
${PROOT} -0 -k ${UTSNAME} sh -c 'hostname hostname2; hostname' | grep ^hostname2$
${PROOT} -0 -k ${UTSNAME} sh -c 'hostname hostname2; uname -n' | grep ^hostname2$
