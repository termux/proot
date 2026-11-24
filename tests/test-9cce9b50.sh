if [ -z "$(which mcookie)" ] || [ -z "$(which gcc)" ] || [ -z "$(which tar)" ] || [ -z "$(which cp)" ] || [ -z "$(which find)" ] || [ -z "$(which ln)" ] || [ -z "$(which ls)" ] || [ -z "$(which sort)" ] || [ -z "$(which cat)" ]; then
    exit 125;
fi

# link2symlink keeps the files that make a faked hard link work -- the
# intermediate ".l2s.<name>0001" and the final ".l2s.<name>0001.<count>"
# -- next to the first name of the file, unless PROOT_L2S_DIR is set.
# They were listed like any name of the file, so:
#
# - "cp -a" and tar(1) made them names of the copy, where they collided
#   with the files of the chain of the copy itself: "cp -a" failed with
#   "cannot create hard link ...: No such file or directory" when it
#   listed them in the wrong order, as f2fs does;
#
# - "rm -rf" removed them at the names it had listed, while removing the
#   names of the file renamed the final one, which was left behind;
#
# - their own names got chains of their own, ".l2s..l2s.a0001.00030001"
#   for instance, taken for a file with 30001 links.
#
# They are left out of listings now, and rmdir(2) removes those that
# would be all that is left in a directory.

export LC_ALL=C

DIR=${TMPDIR:?}/$(mcookie).l2s
SCRIPT_DIR=$(dirname "$0")
mkdir -p "${DIR}/tree/sub" "${DIR}/l2s"

if ! gcc "${SCRIPT_DIR}/getdents.c" -o "${DIR}/getdents" >/dev/null 2>&1; then
    rm -rf "${DIR}"
    exit 125
fi

cd "${DIR}"
echo hello > tree/a
${PROOT} -l ln tree/a tree/b
${PROOT} -l ln tree/a tree/sub/c

# Note: "find -printf %n" reports the link count lstat(2) does.
files() {
    ${PROOT} -l find "$1" -type f -printf "%n %P\n" | sort | tr '\n' ' '
}

set +e
RESULT=$(
I=.l2s.a0001
F=.l2s.a0001.0003

echo "list [$(${PROOT} -l ls -A tree | tr '\n' ' ')] [$(files tree)]"

# Every listing, with a buffer of a single entry too: getdents(2) is
# made again when it returned nothing but files of a chain.  The names
# listed, and how many different numbers of times they are: each one
# is in every listing.  The prober checks d_type against lstat(2).
names() {
    echo "[$(echo "$1" | awk '{ print $2 }' | sort -u | tr '\n' ' ')]" \
         "$(echo "$1" | awk '{ print $2 }' | sort | uniq -c | awk '{ print $1 }' | sort -u | wc -l)"
}
LISTING=$(${PROOT} -l ./getdents tree)
echo "getdents $? $(names "${LISTING}")"

# The same with hidden_files, that may make it again as well.
touch tree/.proot.hidden
LISTING=$(${PROOT} -l -H ./getdents tree)
echo "-H $? $(names "${LISTING}")"
rm tree/.proot.hidden

${PROOT} -l cp -a tree copy
echo "cp $? [$(files copy)]"

${PROOT} -l tar -cf tree.tar tree
echo "tar $? [$(tar -tf tree.tar | sort | tr '\n' ' ')]"

# Archives made before contain them, named after the first name of the
# file: those that collide with the chain of the extracted file stand
# for that very file, the others are names like any other.
N=0
for ORDER in "a $I $F b sub/c" "$F a b $I sub/c" "a b $F sub/c $I" "b sub/c $I a $F"; do
    N=$((N + 1))
    mkdir "x${N}"
    ${PROOT} -l tar -C tree -cf "x${N}.tar" ${ORDER}
    ${PROOT} -l tar -C "x${N}" -xf "x${N}.tar"
    echo "x${N} $? [$(files "x${N}")] [$(${PROOT} -l cat "x${N}/a" "x${N}/b" "x${N}/sub/c" | tr '\n' ' ')]"
done

for D in tree copy x1 x2 x3 x4; do
    ${PROOT} -l rm -rf "${D}"
    echo "rm ${D} $? $(ls -A . | grep -c "^${D}\$")"
done

# The files of the chain stay next to the first name, so they are all
# that's left in its directory once that name is removed.  The other
# names are dangling then, as when "rm -rf" removed these files.
mkdir -p c1/x c1/y c2/x c2/y
echo d > c1/x/a; ${PROOT} -l ln c1/x/a c1/y/b
echo d > c2/x/a; ${PROOT} -l ln c2/x/a c2/y/b
${PROOT} -l rm -rf c1
echo "rm c1 $? $(ls -A . | grep -c '^c1$')"
${PROOT} -l sh -c 'rm c2/x/a && rmdir c2/x; echo "rmdir $? [$(ls -A c2)]"'

# The same when its tracee was granted the permission to remove it for
# the duration of rmdir(2) only.
mkdir -p ro/x ro/y
echo d > ro/x/a; ${PROOT} -l ln ro/x/a ro/y/b
chmod 555 ro/x
${PROOT} -0 -l rm -rf ro
echo "rm ro $? $(ls -A . | grep -c '^ro$')"
chmod -R u+w ro 2>/dev/null

# What's left of a broken chain is shown, and still in the way.
mkdir broken
echo q > broken/.l2s.q0001.0002
${PROOT} -l sh -c 'echo "broken [$(ls -A broken)]"; rmdir broken 2>/dev/null; echo "rmdir $?"'

# The l2s directory looks empty, yet it is not removed.
echo 7 > g
PROOT_L2S_DIR="${DIR}/l2s" ${PROOT} -l sh -c '
ln g h
echo "l2s [$(ls -A l2s)]"
rm -rf l2s 2>/dev/null; echo "rm l2s $? $(cat h)"
'
)
STATUS=$?
set -e

cd /
rm -rf "${DIR}"

if [ ${STATUS} -eq 125 ]; then
    exit 125
fi

EXPECTED='list [a b sub ] [3 a 3 b 3 sub/c ]
getdents 0 [a b sub ] 1
-H 0 [a b sub ] 1
cp 0 [3 a 3 b 3 sub/c ]
tar 0 [tree/ tree/a tree/b tree/sub/ tree/sub/c ]
x1 0 [5 .l2s.a0001 5 .l2s.a0001.0003 5 a 5 b 5 sub/c ] [hello hello hello ]
x2 0 [5 .l2s.a0001 5 .l2s.a0001.0003 5 a 5 b 5 sub/c ] [hello hello hello ]
x3 0 [3 a 3 b 3 sub/c ] [hello hello hello ]
x4 0 [5 .l2s.a0001 5 .l2s.a0001.0003 5 a 5 b 5 sub/c ] [hello hello hello ]
rm tree 0 0
rm copy 0 0
rm x1 0 0
rm x2 0 0
rm x3 0 0
rm x4 0 0
rm c1 0 0
rmdir 0 [y]
rm ro 0 0
broken [.l2s.q0001.0002]
rmdir 1
l2s []
rm l2s 1 7'

if [ "${RESULT}" != "${EXPECTED}" ]; then
    echo "${RESULT}"
    exit 1
fi

exit 0
