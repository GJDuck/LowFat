#!/bin/bash
#
# _|                                      _|_|_|_|            _|
# _|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
# _|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
# _|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
# _|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|
#
# Gregory J. Duck
#

LEGACY=no
BUILD_PLUGIN=no
VERSION=`cat VERSION`
if [ $LEGACY = yes ]
then
    VERSION=${VERSION}-LEGACY
fi
if [ $# != 0 ]
then
    VERSION=${VERSION}-CUSTOM
fi
RELEASE_NAME=lowfat-$VERSION

build_llvm()
{
    echo -e "${GREEN}$0${OFF}: copying the LowFat config files..."
    RUNTIME_PATH=llvm-4.0.0.src/projects/compiler-rt/lib/lowfat/
    INSTRUMENTATION_PATH=llvm-4.0.0.src/lib/Transforms/Instrumentation/
    CLANGLIB_PATH=llvm-4.0.0.src/tools/clang/lib/Basic/
    (cd config; cp lowfat_config.h lowfat_config.c ../${RUNTIME_PATH}/.)
    ln -fs "$PWD/${RUNTIME_PATH}/lowfat_config.c" \
        "$PWD/$INSTRUMENTATION_PATH/lowfat_config.inc"
    ln -fs "$PWD/${RUNTIME_PATH}/lowfat_config.h" \
        "$PWD/$INSTRUMENTATION_PATH/lowfat_config.h"
    ln -fs "$PWD/${RUNTIME_PATH}/lowfat_config.h" \
        "$PWD/$CLANGLIB_PATH/lowfat_config.h"
    ln -fs "$PWD/${RUNTIME_PATH}/lowfat.h" \
        "$PWD/$INSTRUMENTATION_PATH/lowfat.h"

    if [ ! -f "$PWD/${RUNTIME_PATH}/CMakeLists.txt" ]
    then
        if [ x$LEGACY = xno ]
        then
            ln -fs "$PWD/${RUNTIME_PATH}/CMakeLists.txt.modern" \
                "$PWD/${RUNTIME_PATH}/CMakeLists.txt"
        else
            ln -fs "$PWD/${RUNTIME_PATH}/CMakeLists.txt.legacy" \
                "$PWD/${RUNTIME_PATH}/CMakeLists.txt"
        fi
    fi

    BUILD_PATH=$1
    if [ -e $BUILD_PATH ]
    then
        CONFIGURE=false
        echo -e \
        "${GREEN}$0${OFF}: using existing LLVM build directory ($BUILD_PATH)..."
    else
        CONFIGURE=true
        echo -e \
        "${GREEN}$0${OFF}: creating LLVM build directory ($BUILD_PATH)..."
        mkdir -p $BUILD_PATH
    fi
    
    echo -e \
        "${GREEN}$0${OFF}: installing the LowFat ld script file..."
    mkdir -p $BUILD_PATH/lib/LowFat/
    cp config/lowfat.ld $BUILD_PATH/lib/LowFat/
    
    echo -e "${GREEN}$0${OFF}: will now build LLVM..."
    cd $BUILD_PATH
    
    if [ x$CONFIGURE = xtrue ]
    then
        CC=$CLANG CXX=$CLANGXX cmake ../llvm-4.0.0.src/ \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=install \
            -DBUILD_SHARED_LIBS=ON \
            -DLLVM_TARGETS_TO_BUILD="X86" \
            -DLLVM_BINUTILS_INCDIR=/usr/include
    fi
    make -j `nproc` install install-clang
    rm -rf "../$RELEASE_NAME"
    mv install "../$RELEASE_NAME"
    cd ..
    echo

    if [ x$BUILD_PLUGIN = xyes ]
    then
        echo -e "${GREEN}$0${OFF}: creating LowFat.so plugin..."
        # These should not fail if we got this far:
        $CLANGXX -DLOWFAT_PLUGIN "$PWD/$INSTRUMENTATION_PATH/LowFat.cpp" \
            -c -Wall -O2 -I "$PWD/$INSTRUMENTATION_PATH/" -o LowFat.o \
            `$LLVM_CONFIG --cxxflags` \
            `$LLVM_CONFIG --includedir` >/dev/null 2>&1
        $CLANGXX -shared -rdynamic -o LowFat.so LowFat.o \
            `$LLVM_CONFIG --ldflags` >/dev/null 2>&1
        rm -f LowFat.o LowFat.dwo
    fi

    if [ x$BUILD_STANDALONE = xyes ]
    then
        echo -e "${GREEN}$0${OFF}: creating liblowfat.preload.so standalone..."
        if [ $LEGACY = no ]
        then
            STANDALONE_OPTS="-mbmi -mbmi2 -mlzcnt"
        else
            STANDALONE_OPTS="-mno-bmi -mno-bmi2 -mno-lzcnt"
        fi
        $CLANG -D_GNU_SOURCE -DLOWFAT_STANDALONE -fPIC -shared \
            -o liblowfat.preload.so -std=gnu99 -m64 "-I$PWD/${RUNTIME_PATH}/" \
            -DLOWFAT_LINUX -O2 $STANDALONE_OPTS "$PWD/${RUNTIME_PATH}/lowfat.c"
        echo -e "${GREEN}$0${OFF}: creating liblowfat.so standalone..."
        $CLANG -D_GNU_SOURCE -DLOWFAT_STANDALONE \
            -DLOWFAT_NO_REPLACE_STD_MALLOC -fPIC -shared \
            -o liblowfat.so -std=gnu99 -m64 "-I$PWD/${RUNTIME_PATH}/" \
            -DLOWFAT_LINUX -O2 $STANDALONE_OPTS "$PWD/${RUNTIME_PATH}/lowfat.c"
        echo -e "${GREEN}$0${OFF}: creating lowfat.o standalone..."
        $CLANG -D_GNU_SOURCE -DLOWFAT_STANDALONE \
            -DLOWFAT_NO_REPLACE_STD_MALLOC -c -fPIC \
            -o lowfat.o -std=gnu99 -m64 "-I$PWD/${RUNTIME_PATH}/" \
            -DLOWFAT_LINUX -O2 $STANDALONE_OPTS "$PWD/${RUNTIME_PATH}/lowfat.c"
    fi

    echo -e "${GREEN}$0${OFF}: cleaning up the LowFat config files..."
    rm -f "$PWD/${RUNTIME_PATH}/lowfat_config.h" \
          "$PWD/${RUNTIME_PATH}/lowfat_config.c" \
          "$PWD/$INSTRUMENTATION_PATH/lowfat_config.inc" \
          "$PWD/$INSTRUMENTATION_PATH/lowfat_config.h" \
          "$PWD/$INSTRUMENTATION_PATH/lowfat.h" \
          "$PWD/$CLANGLIB_PATH/lowfat_config.h"
}

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

if [ $# = 0 ]
then
    CONFIG="sizes.cfg 32"
    echo -e \
        "${GREEN}$0${OFF}: using the default LowFat configuration ($CONFIG)..."
else
    CONFIG=$@
    echo -e "${GREEN}$0${OFF}: using custom LowFat configuration ($CONFIG)..."
fi

CMAKE=`which cmake`
if [ -z "$CMAKE" ]
then
    echo -e "${GREEN}$0${OFF}: ${RED}ERROR${OFF}: cmake is not installed!"
    exit 1
fi

CLANG=`which clang-4.0`
CLANGXX=`which clang++-4.0`
LLVM_CONFIG=`which llvm-config-4.0`
HAVE_CLANG_4=false
if [ -z "$CLANG" -o -z "$CLANGXX" -o -z "$LLVM_CONFIG" ]
then
    echo -e "${GREEN}$0${OFF}: ${YELLOW}warning${OFF}: one or more of clang-4.0/clang++-4.0/llvm-config-4.0 is not installed!"
    echo -e "${GREEN}$0${OFF}: will try gcc."
    CLANG=`which gcc`
    CLANGXX=`which g++`
    if [ -z "$CLANG" -o -z "$CLANGXX" ]
    then
        echo -e "${GREEN}$0${OFF}: ${RED}ERROR${OFF}: one or more of gcc/g++ is not installed!"
        exit 1
    fi
else
    HAVE_CLANG_4=true
fi

set -e

echo -n -e "${GREEN}$0${OFF}: checking the CPU..."
if grep ' bmi1' /proc/cpuinfo > /dev/null
then
    echo -n "[bmi]"
else
    echo
    echo -e "${GREEN}$0${OFF}: ${YELLOW}warning${OFF}: CPU does not support BMI"
    LEGACY=yes
fi
if grep ' bmi2' /proc/cpuinfo > /dev/null
then
    echo -n "[bmi2]"
else
    echo
    echo -e \
        "${GREEN}$0${OFF}: ${YELLOW}warning${OFF}: CPU does not support BMI2"
    LEGACY=yes
fi
if grep ' abm' /proc/cpuinfo > /dev/null
then
    echo "[lzcnt]"
else
    echo
    echo -e \
        "${GREEN}$0${OFF}: ${YELLOW}warning${OFF}: CPU does not support LZCNT"
    LEGACY=yes
fi

echo -e "${GREEN}$0${OFF}: building the LowFat config builder..."
(cd config; CC=$CLANG CFLAGS="-std=gnu99" CXX=$CLANGXX make >/dev/null)

echo -e "${GREEN}$0${OFF}: building the LowFat config..."
(cd config; ./lowfat-config $CONFIG > lowfat-config.log)

echo -e "${GREEN}$0${OFF}: building the LowFat config check..."
(cd config; CC=$CLANG CLFAGS="-std=gnu99" CXX=$CLANGXX make lowfat-check-config >/dev/null)

echo -e "${GREEN}$0${OFF}: checking the LowFat config..."
if config/lowfat-check-config >/dev/null 2>&1
then
    CHECK=true
else
    CHECK=false
fi

if [ x$CHECK != xtrue ]
then
    echo -e "${GREEN}$0${OFF}: ${RED}ERROR${OFF}: configuration check failed!"
    config/lowfat-check-config
    exit 1
fi

echo -e "${GREEN}$0${OFF}: building the LowFat pointer info tool..."
(cd config; CC=$CLANG CFLAGS="-std=gnu99" CXX=$CLANGXX make lowfat-ptr-info >/dev/null)

if [ x$HAVE_CLANG_4 = xfalse ]
then
    BOOTSTRAP_PATH=bootstrap
    CLANG_TMP="$PWD/$BOOTSTRAP_PATH/bin/clang"
    CLANGXX_TMP="$PWD/$BOOTSTRAP_PATH/bin/clang++"
    LLVM_CONFIG_TMP="$PWD/$BOOTSTRAP_PATH/bin/llvm-config"
    if [ ! -x "$CLANG_TMP" -o ! -x "$CLANGXX_TMP" -o ! -x "$LLVM_CONFIG_TMP" ]
    then
        echo -e \
        "${GREEN}$0${OFF}: clang-4.0 is not installed; bootstrapping LLVM..."
        build_llvm $BOOTSTRAP_PATH
    fi
    CLANG=$CLANG_TMP
    CLANGXX=$CLANGXX_TMP
    LLVM_CONFIG=$LLVM_CONFIG_TMP
    HAVE_CLANG_4=true
fi

BUILD_PATH=build
BUILD_PLUGIN=yes
BUILD_STANDALONE=yes
build_llvm $BUILD_PATH

echo -e "${GREEN}$0${OFF}: installing the LowFat pointer info tool..."
cp config/lowfat-ptr-info $BUILD_PATH/bin/

echo -e "${GREEN}$0${OFF}: building test program..."
(cd test; make clean >/dev/null 2>&1; make >/dev/null 2>&1)

echo -n -e "${GREEN}$0${OFF}: testing LowFat build..."
if test/Test >test.tmp 2>&1
then
    TEST_PASSED=true
else
    TEST_PASSED=false
fi
sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" < test.tmp > test.log
rm -f test.tmp
(cd test; make clean >/dev/null 2>&1)
if [ x$TEST_PASSED = xtrue ]
then
    echo "ok"
else
    echo "failed!"
    echo -n -e \
        "${GREEN}$0${OFF}: ${RED}ERROR${OFF}: LowFat failed to build correctly"
    echo " (see test.log for more information)"
    exit 1
fi

echo -e "${GREEN}$0${OFF}: building release package..."
rm -f "$RELEASE_NAME.tar.xz"
tar cvJ --owner root --group root -f "$RELEASE_NAME.tar.xz" "$RELEASE_NAME"

echo -e "${GREEN}$0${OFF}: build is complete!"
echo -e \
    "${GREEN}$0${OFF}: clang with LowFat is available here: $PWD/bin/clang"
echo -e \
    "${GREEN}$0${OFF}: clang++ with LowFat is available here: $PWD/bin/clang++"
echo -e "${YELLOW}"
echo "_|                                      _|_|_|_|            _|"
echo "_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|"
echo "_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|"
echo "_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|"
echo "_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|"
echo -e "${OFF}"
echo "USAGE:"
echo -e "${BOLD}      $PWD/$BUILD_PATH/bin/clang -fsanitize=lowfat program.c${OFF}"
echo -e "${BOLD}      $PWD/$BUILD_PATH/bin/clang++ -fsanitize=lowfat program.cpp${OFF}"
echo -e "${BOLD}      $PWD/$BUILD_PATH/bin/lowfat-ptr-info <pointer-hex-value>${OFF}"
echo
echo "EXAMPLE:"
echo -e "${BOLD}      \$ cd test${OFF}"
echo -e "${BOLD}      \$ $PWD/$BUILD_PATH/bin/clang -fsanitize=lowfat -O2 test_input_heap.c${OFF}"
echo -e "${BOLD}      \$ ./a.out 15${OFF}"
echo "      Enter a string: A short string"
echo "      String = \"a short string\""
echo -e "${BOLD}      \$ ./a.out 15${OFF}"
echo "      Enter a string: A loooooooooooooong string"
echo "      LOWFAT ERROR: out-of-bounds error detected!"
echo "          operation = write"
echo "          pointer   = 0x8dcb3a430 (heap)"
echo "          base      = 0x8dcb3a420"
echo "          size      = 16"
echo "          overflow  = +0"
echo

if [ $LEGACY = yes ]
then
    echo "------------------------------------------------------------------"
    echo -e "${YELLOW}*** LEGACY MODE WARNING ***${OFF}"
    echo
    echo "LowFat has been compiled in LEGACY mode for older CPUs.  This mode:"
    echo "    (1) is not officially supported; and"
    echo "    (2) has some features disabled."
    echo
    echo "------------------------------------------------------------------"
fi

