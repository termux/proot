#!/bin/sh
set -ex
ndk_ver="r27c"
clang_ver="18"
talloc_ver="2.4.3"

if [ -z $ANDROID_API ]; then
	echo "Missing \$ANDROID_API environment variable" >&2
	exit 2
fi

case ${ARCH} in
	x86_64)
		;;
	aarch64)
		if [ "$ARCH" = aarch64 ]; then
			IS_AARCH64=true
		fi
		;;
	*)
		echo "Unknown \$ARCH '$ARCH'" >&2
		exit 2
esac

oldpath=$(pwd)

mkdir -p ./build/
cd ./build/

# TODO: figure out android ndk license
if [ ! -e android-ndk-"$ndk_ver" ]; then
	# unpack Android NDK
	curl -fsSLO https://dl.google.com/android/repository/android-ndk-"$ndk_ver"-linux.zip
	unzip android-ndk-"$ndk_ver"-linux.zip
	rm android-ndk-"$ndk_ver"-linux.zip
fi

export ANDROID_NDK_ROOT=$(pwd)/android-ndk-"$ndk_ver"

mkdir -p "$ARCH"
cd "$ARCH"

# export compile flags for talloc and proot
export CC="$ANDROID_NDK_ROOT"/toolchains/llvm/prebuilt/linux-x86_64/bin/"$ARCH"-linux-android"$ANDROID_API"-clang
export CXX="$ANDROID_NDK_ROOT"/toolchains/llvm/prebuilt/linux-x86_64/bin/"$ARCH"-linux-android"$ANDROID_API"-clang++
export AR="$ANDROID_NDK_ROOT"/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar
export STRIP="$ANDROID_NDK_ROOT"/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip
export OBJCOPY="$ANDROID_NDK_ROOT"/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy
export OBJDUMP="$ANDROID_NDK_ROOT"/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump

if [ ! -e samba-talloc-"$talloc_ver" ]; then
	curl -fsSLO https://github.com/samba-team/samba/archive/refs/tags/talloc-"$talloc_ver".tar.gz
	tar -xf talloc-"$talloc_ver".tar.gz
	rm talloc-"$talloc_ver".tar.gz

	cd ./samba-talloc-"$talloc_ver"/lib/talloc/
	cat <<EOF > cross-answers.txt
Checking uname sysname type: "Linux"
Checking uname machine type: "dontcare"
Checking uname release type: "dontcare"
Checking uname version type: "dontcare"
Checking simple C program: OK
rpath library support: OK
-Wl,--version-script support: FAIL
Checking getconf LFS_CFLAGS: OK
Checking for large file support without additional flags: OK
Checking for -D_FILE_OFFSET_BITS=64: OK
Checking for -D_LARGE_FILES: OK
Checking correct behavior of strtoll: OK
Checking for working strptime: OK
Checking for C99 vsnprintf: OK
Checking for HAVE_SHARED_MMAP: OK
Checking for HAVE_MREMAP: OK
Checking for HAVE_INCOHERENT_MMAP: OK
Checking for HAVE_SECURE_MKSTEMP: OK
Checking getconf large file support flags work: OK
Checking for HAVE_IFACE_IFCONF: FAIL
EOF

	./configure build --disable-rpath --disable-python --cross-compile --cross-answers ./cross-answers.txt

	mkdir -p include
	mkdir -p lib

	cp ./talloc.h ./include/
	$AR rcs ./lib/libtalloc.a ./bin/default/lib/talloc/talloc.*.o

	cd ./../../../
fi

export CFLAGS=-I"$(pwd)"/samba-talloc-"$talloc_ver"/lib/talloc/include
export LDFLAGS=-L"$(pwd)"/samba-talloc-"$talloc_ver"/lib/talloc/lib

cd "$oldpath"/src/

export LDFLAGS=""$LDFLAGS" -static"

make
