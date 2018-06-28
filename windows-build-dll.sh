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

echo -e "${GREEN}$0${OFF}"
echo
echo "This script builds an experimental Windows port of the LowFat runtime."
echo -e "This script does ${YELLOW}*not*${OFF} build the modified LowFat clang/LLVM for Windows."
echo "(For the latter only Linux is supported)."
echo
read -p "[Press ENTER to continue]"

CC=x86_64-w64-mingw32-gcc

if [ ! -e "`which $CC`" ]
then
    echo -e \
		"${GREEN}$0${OFF}: ${RED}ERROR${OFF}: $CC (MinGW) is not installed" 2>&1
    exit 1
fi

echo -e "${GREEN}$0${OFF}: build lowfat.dll..."
COPTS="-Wall -O2 -mno-bmi -mno-bmi2 -mno-lzcnt -Iconfig/windows
    -DLOWFAT_STANDALONE -DLOWFAT_WINDOWS"
SRC=llvm-4.0.0.src/projects/compiler-rt/lib/lowfat/
$CC -shared $COPTS -c "$SRC/lowfat.c" -o lowfat.obj
$CC -shared $COPTS -Wl,--entry=lowfat_dll_entry -o lowfat.dll lowfat.obj
echo -e "${GREEN}$0${OFF}: build lowfat_test.exe..."
$CC $COPTS "-I$SRC" test/test_windows.c -o lowfat_test.exe -L. -llowfat

