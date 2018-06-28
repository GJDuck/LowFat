/*
 *   _|                                      _|_|_|_|            _|
 *   _|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
 *   _|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
 *   _|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
 *   _|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|
 * 
 * Gregory J. Duck.
 *
 * Copyright (c) 2018 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

/*
 * This is a fixed configuration for the Windows build.
 */

#include "lowfat_config.h"

#define LOWFAT_NUM_REGIONS 61
#define LOWFAT_SIZES_PAGES 1
#define LOWFAT_REGION_SIZE _LOWFAT_REGION_SIZE
#define LOWFAT_REGION_SIZE_SHIFT 35
#define LOWFAT_STACK_MEMORY_SIZE 4294967296
#define LOWFAT_GLOBAL_MEMORY_SIZE 17179869184
#define LOWFAT_HEAP_MEMORY_SIZE 12884836352
#define LOWFAT_STACK_MEMORY_OFFSET 30064771072
#define LOWFAT_GLOBAL_MEMORY_OFFSET 12884865024
#define LOWFAT_HEAP_MEMORY_OFFSET 0
#define LOWFAT_STACK_SIZE 67108864
#define LOWFAT_PAGE_SIZE 4096
#define LOWFAT_HEAP_ASLR_MASK 0xFFFFFFFFull
#define LOWFAT_MAX_HEAP_ALLOC_SIZE 8589934592
#define LOWFAT_TID_OFFSET 0x2d0
#define LOWFAT_JOINID_OFFSET 0x628
#define LOWFAT_NO_MEMORY_ALIAS 1
#define LOWFAT_NO_REPLACE_STD_MALLOC 1
#define LOWFAT_MAX_STACK_ALLOC_SIZE 33554432
#define LOWFAT_MAX_GLOBAL_ALLOC_SIZE 67108864
#define LOWFAT_MIN_ALLOC_SIZE 16
#define LOWFAT_NUM_STACK_REGIONS 53
#define LOWFAT_STACK_REGION 62

#define LOWFAT_CONST_DATA
#define LOWFAT_NO_STD_MALLOC_FALLBACK 1
#define LOWFAT_LEGACY 1

static const LOWFAT_CONST_DATA size_t lowfat_sizes[] =
{
	16, /* idx=0 */
	32, /* idx=1 */
	48, /* idx=2 */
	64, /* idx=3 */
	80, /* idx=4 */
	96, /* idx=5 */
	112, /* idx=6 */
	128, /* idx=7 */
	144, /* idx=8 */
	160, /* idx=9 */
	192, /* idx=10 */
	224, /* idx=11 */
	256, /* idx=12 */
	272, /* idx=13 */
	320, /* idx=14 */
	384, /* idx=15 */
	448, /* idx=16 */
	512, /* idx=17 */
	528, /* idx=18 */
	640, /* idx=19 */
	768, /* idx=20 */
	896, /* idx=21 */
	1024, /* idx=22 */
	1040, /* idx=23 */
	1280, /* idx=24 */
	1536, /* idx=25 */
	1792, /* idx=26 */
	2048, /* idx=27 */
	2064, /* idx=28 */
	2560, /* idx=29 */
	3072, /* idx=30 */
	3584, /* idx=31 */
	4096, /* idx=32 */
	4112, /* idx=33 */
	5120, /* idx=34 */
	6144, /* idx=35 */
	7168, /* idx=36 */
	8192, /* idx=37 */
	8208, /* idx=38 */
	10240, /* idx=39 */
	12288, /* idx=40 */
	16384, /* idx=41 */
	32768, /* idx=42 */
	65536, /* idx=43 */
	131072, /* idx=44 */
	262144, /* idx=45 */
	524288, /* idx=46 */
	1048576, /* idx=47 */
	2097152, /* idx=48 */
	4194304, /* idx=49 */
	8388608, /* idx=50 */
	16777216, /* idx=51 */
	33554432, /* idx=52 */
	67108864, /* idx=53 */
	134217728, /* idx=54 */
	268435456, /* idx=55 */
	536870912, /* idx=56 */
	1073741824, /* idx=57 */
	2147483648, /* idx=58 */
	4294967296, /* idx=59 */
	8589934592, /* idx=60 */
};

static const LOWFAT_CONST_DATA size_t lowfat_magics[] =
{
	0x1000000000000001ull, /* idx=0, size=16 */
	0x0800000000000001ull, /* idx=1, size=32 */
	0x0555555555555556ull, /* idx=2, size=48 */
	0x0400000000000001ull, /* idx=3, size=64 */
	0x0333333333333334ull, /* idx=4, size=80 */
	0x02AAAAAAAAAAAAABull, /* idx=5, size=96 */
	0x024924924924924Aull, /* idx=6, size=112 */
	0x0200000000000001ull, /* idx=7, size=128 */
	0x01C71C71C71C71C8ull, /* idx=8, size=144 */
	0x019999999999999Aull, /* idx=9, size=160 */
	0x0155555555555556ull, /* idx=10, size=192 */
	0x0124924924924925ull, /* idx=11, size=224 */
	0x0100000000000001ull, /* idx=12, size=256 */
	0x00F0F0F0F0F0F0F1ull, /* idx=13, size=272 */
	0x00CCCCCCCCCCCCCDull, /* idx=14, size=320 */
	0x00AAAAAAAAAAAAABull, /* idx=15, size=384 */
	0x0092492492492493ull, /* idx=16, size=448 */
	0x0080000000000001ull, /* idx=17, size=512 */
	0x007C1F07C1F07C20ull, /* idx=18, size=528 */
	0x0066666666666667ull, /* idx=19, size=640 */
	0x0055555555555556ull, /* idx=20, size=768 */
	0x004924924924924Aull, /* idx=21, size=896 */
	0x0040000000000001ull, /* idx=22, size=1024 */
	0x003F03F03F03F040ull, /* idx=23, size=1040 */
	0x0033333333333334ull, /* idx=24, size=1280 */
	0x002AAAAAAAAAAAABull, /* idx=25, size=1536 */
	0x0024924924924925ull, /* idx=26, size=1792 */
	0x0020000000000001ull, /* idx=27, size=2048 */
	0x001FC07F01FC07F1ull, /* idx=28, size=2064 */
	0x001999999999999Aull, /* idx=29, size=2560 */
	0x0015555555555556ull, /* idx=30, size=3072 */
	0x0012492492492493ull, /* idx=31, size=3584 */
	0x0010000000000001ull, /* idx=32, size=4096 */
	0x000FF00FF00FF010ull, /* idx=33, size=4112 */
	0x000CCCCCCCCCCCCDull, /* idx=34, size=5120 */
	0x000AAAAAAAAAAAABull, /* idx=35, size=6144 */
	0x000924924924924Aull, /* idx=36, size=7168 */
	0x0008000000000001ull, /* idx=37, size=8192 */
	0x0007FC01FF007FC1ull, /* idx=38, size=8208 */
	0x0006666666666667ull, /* idx=39, size=10240 */
	0x0005555555555556ull, /* idx=40, size=12288 */
	0x0004000000000001ull, /* idx=41, size=16384 */
	0x0002000000000001ull, /* idx=42, size=32768 */
	0x0001000000000001ull, /* idx=43, size=65536 */
	0x0000800000000001ull, /* idx=44, size=131072 */
	0x0000400000000001ull, /* idx=45, size=262144 */
	0x0000200000000001ull, /* idx=46, size=524288 */
	0x0000100000000001ull, /* idx=47, size=1048576 */
	0x0000080000000001ull, /* idx=48, size=2097152 */
	0x0000040000000001ull, /* idx=49, size=4194304 */
	0x0000020000000001ull, /* idx=50, size=8388608 */
	0x0000010000000001ull, /* idx=51, size=16777216 */
	0x0000008000000001ull, /* idx=52, size=33554432 */
	0x0000004000000001ull, /* idx=53, size=67108864 */
	0x0000002000000001ull, /* idx=54, size=134217728 */
	0x0000001000000001ull, /* idx=55, size=268435456 */
	0x0000000800000001ull, /* idx=56, size=536870912 */
	0x0000000400000001ull, /* idx=57, size=1073741824 */
	0x0000000200000001ull, /* idx=58, size=2147483648 */
	0x0000000100000001ull, /* idx=59, size=4294967296 */
	0x0000000080000001ull, /* idx=60, size=8589934592 */
};

static const LOWFAT_CONST_DATA size_t lowfat_stacks[] =
{
	1,
	2,
	4,
	8,
	13,
	18,
	23,
	28,
	33,
	38,
	42,
	43,
	44,
	45,
	46,
	47,
	48,
	49,
	50,
	51,
	52,
	53,
	62,
	0,
};

const LOWFAT_CONST_DATA size_t lowfat_stack_sizes[64+1] =
{
	0, /* idx=0 */
	0, /* idx=1 */
	0, /* idx=2 */
	0, /* idx=3 */
	0, /* idx=4 */
	0, /* idx=5 */
	0, /* idx=6 */
	0, /* idx=7 */
	0, /* idx=8 */
	0, /* idx=9 */
	0, /* idx=10 */
	0, /* idx=11 */
	0, /* idx=12 */
	0, /* idx=13 */
	0, /* idx=14 */
	0, /* idx=15 */
	0, /* idx=16 */
	0, /* idx=17 */
	0, /* idx=18 */
	0, /* idx=19 */
	0, /* idx=20 */
	0, /* idx=21 */
	0, /* idx=22 */
	0, /* idx=23 */
	0, /* idx=24 */
	0, /* idx=25 */
	0, /* idx=26 */
	0, /* idx=27 */
	0, /* idx=28 */
	0, /* idx=29 */
	0, /* idx=30 */
	0, /* idx=31 */
	0, /* idx=32 */
	0, /* idx=33 */
	0, /* idx=34 */
	0, /* idx=35 */
	0, /* idx=36 */
	0, /* idx=37 */
	0, /* idx=38 */
	33554432, /* idx=39 */
	16777216, /* idx=40 */
	8388608, /* idx=41 */
	4194304, /* idx=42 */
	2097152, /* idx=43 */
	1048576, /* idx=44 */
	524288, /* idx=45 */
	262144, /* idx=46 */
	131072, /* idx=47 */
	65536, /* idx=48 */
	32768, /* idx=49 */
	16384, /* idx=50 */
	8192, /* idx=51 */
	4096, /* idx=52 */
	2048, /* idx=53 */
	1024, /* idx=54 */
	512, /* idx=55 */
	256, /* idx=56 */
	128, /* idx=57 */
	64, /* idx=58 */
	32, /* idx=59 */
	16, /* idx=60 */
	16, /* idx=61 */
	16, /* idx=62 */
	16, /* idx=63 */
	16, /* idx=64 */
};

const LOWFAT_CONST_DATA size_t lowfat_stack_masks[64+1] =
{
	0, /* idx=0 */
	0, /* idx=1 */
	0, /* idx=2 */
	0, /* idx=3 */
	0, /* idx=4 */
	0, /* idx=5 */
	0, /* idx=6 */
	0, /* idx=7 */
	0, /* idx=8 */
	0, /* idx=9 */
	0, /* idx=10 */
	0, /* idx=11 */
	0, /* idx=12 */
	0, /* idx=13 */
	0, /* idx=14 */
	0, /* idx=15 */
	0, /* idx=16 */
	0, /* idx=17 */
	0, /* idx=18 */
	0, /* idx=19 */
	0, /* idx=20 */
	0, /* idx=21 */
	0, /* idx=22 */
	0, /* idx=23 */
	0, /* idx=24 */
	0, /* idx=25 */
	0, /* idx=26 */
	0, /* idx=27 */
	0, /* idx=28 */
	0, /* idx=29 */
	0, /* idx=30 */
	0, /* idx=31 */
	0, /* idx=32 */
	0, /* idx=33 */
	0, /* idx=34 */
	0, /* idx=35 */
	0, /* idx=36 */
	0, /* idx=37 */
	0, /* idx=38 */
	0xFFFFFFFFFE000000ull,	/* idx=39, size=33554432 */
	0xFFFFFFFFFF000000ull,	/* idx=40, size=16777216 */
	0xFFFFFFFFFF800000ull,	/* idx=41, size=8388608 */
	0xFFFFFFFFFFC00000ull,	/* idx=42, size=4194304 */
	0xFFFFFFFFFFE00000ull,	/* idx=43, size=2097152 */
	0xFFFFFFFFFFF00000ull,	/* idx=44, size=1048576 */
	0xFFFFFFFFFFF80000ull,	/* idx=45, size=524288 */
	0xFFFFFFFFFFFC0000ull,	/* idx=46, size=262144 */
	0xFFFFFFFFFFFE0000ull,	/* idx=47, size=131072 */
	0xFFFFFFFFFFFF0000ull,	/* idx=48, size=65536 */
	0xFFFFFFFFFFFF8000ull,	/* idx=49, size=32768 */
	0xFFFFFFFFFFFFC000ull,	/* idx=50, size=16384 */
	0xFFFFFFFFFFFFE000ull,	/* idx=51, size=8192 */
	0xFFFFFFFFFFFFF000ull,	/* idx=52, size=4096 */
	0xFFFFFFFFFFFFF800ull,	/* idx=53, size=2048 */
	0xFFFFFFFFFFFFFC00ull,	/* idx=54, size=1024 */
	0xFFFFFFFFFFFFFE00ull,	/* idx=55, size=512 */
	0xFFFFFFFFFFFFFF00ull,	/* idx=56, size=256 */
	0xFFFFFFFFFFFFFF80ull,	/* idx=57, size=128 */
	0xFFFFFFFFFFFFFFC0ull,	/* idx=58, size=64 */
	0xFFFFFFFFFFFFFFE0ull,	/* idx=59, size=32 */
	0xFFFFFFFFFFFFFFF0ull,	/* idx=60, size=16 */
	0xFFFFFFFFFFFFFFF0ull,	/* idx=61, size=16 */
	0xFFFFFFFFFFFFFFF0ull,	/* idx=62, size=16 */
	0xFFFFFFFFFFFFFFF0ull,	/* idx=63, size=16 */
	0xFFFFFFFFFFFFFFF0ull,	/* idx=64, size=16 */
};

const LOWFAT_CONST_DATA ssize_t lowfat_stack_offsets[64+1] =
{
	0, /* idx=0 */
	0, /* idx=1 */
	0, /* idx=2 */
	0, /* idx=3 */
	0, /* idx=4 */
	0, /* idx=5 */
	0, /* idx=6 */
	0, /* idx=7 */
	0, /* idx=8 */
	0, /* idx=9 */
	0, /* idx=10 */
	0, /* idx=11 */
	0, /* idx=12 */
	0, /* idx=13 */
	0, /* idx=14 */
	0, /* idx=15 */
	0, /* idx=16 */
	0, /* idx=17 */
	0, /* idx=18 */
	0, /* idx=19 */
	0, /* idx=20 */
	0, /* idx=21 */
	0, /* idx=22 */
	0, /* idx=23 */
	0, /* idx=24 */
	0, /* idx=25 */
	0, /* idx=26 */
	0, /* idx=27 */
	0, /* idx=28 */
	0, /* idx=29 */
	0, /* idx=30 */
	0, /* idx=31 */
	0, /* idx=32 */
	0, /* idx=33 */
	0, /* idx=34 */
	0, /* idx=35 */
	0, /* idx=36 */
	0, /* idx=37 */
	0, /* idx=38 */
	-309237645312,	/* idx=39, size=33554432 */
	-343597383680,	/* idx=40, size=16777216 */
	-377957122048,	/* idx=41, size=8388608 */
	-412316860416,	/* idx=42, size=4194304 */
	-446676598784,	/* idx=43, size=2097152 */
	-481036337152,	/* idx=44, size=1048576 */
	-515396075520,	/* idx=45, size=524288 */
	-549755813888,	/* idx=46, size=262144 */
	-584115552256,	/* idx=47, size=131072 */
	-618475290624,	/* idx=48, size=65536 */
	-652835028992,	/* idx=49, size=32768 */
	-687194767360,	/* idx=50, size=16384 */
	-824633720832,	/* idx=51, size=8192 */
	-996432412672,	/* idx=52, size=4096 */
	-1168231104512,	/* idx=53, size=2048 */
	-1340029796352,	/* idx=54, size=1024 */
	-1511828488192,	/* idx=55, size=512 */
	-1683627180032,	/* idx=56, size=256 */
	-1855425871872,	/* idx=57, size=128 */
	-1992864825344,	/* idx=58, size=64 */
	-2061584302080,	/* idx=59, size=32 */
	-2095944040448,	/* idx=60, size=16 */
	-2095944040448,	/* idx=61, size=16 */
	-2095944040448,	/* idx=62, size=16 */
	-2095944040448,	/* idx=63, size=16 */
	-2095944040448,	/* idx=64, size=16 */
};

static size_t lowfat_heap_select(size_t size)
{
	switch (__builtin_clzll(size))
	{
		case 64:
		case 63:
		case 62:
		case 61:
		case 60:
		case 59:
			if (size <= 16-1-0)
				return 1;
		case 58:
			if (size <= 32-1-0)
				return 2;
			if (size <= 48-1-0)
				return 3;
		case 57:
			if (size <= 64-1-0)
				return 4;
			if (size <= 80-1-0)
				return 5;
			if (size <= 96-1-0)
				return 6;
			if (size <= 112-1-0)
				return 7;
		case 56:
			if (size <= 128-1-0)
				return 8;
			if (size <= 144-1-0)
				return 9;
			if (size <= 160-1-0)
				return 10;
			if (size <= 192-1-0)
				return 11;
			if (size <= 224-1-0)
				return 12;
		case 55:
			if (size <= 256-1-0)
				return 13;
			if (size <= 272-1-0)
				return 14;
			if (size <= 320-1-0)
				return 15;
			if (size <= 384-1-0)
				return 16;
			if (size <= 448-1-0)
				return 17;
		case 54:
			if (size <= 512-1-0)
				return 18;
			if (size <= 528-1-0)
				return 19;
			if (size <= 640-1-0)
				return 20;
			if (size <= 768-1-0)
				return 21;
			if (size <= 896-1-0)
				return 22;
		case 53:
			if (size <= 1024-1-0)
				return 23;
			if (size <= 1040-1-0)
				return 24;
			if (size <= 1280-1-0)
				return 25;
			if (size <= 1536-1-0)
				return 26;
			if (size <= 1792-1-0)
				return 27;
		case 52:
			if (size <= 2048-1-0)
				return 28;
			if (size <= 2064-1-0)
				return 29;
			if (size <= 2560-1-0)
				return 30;
			if (size <= 3072-1-0)
				return 31;
			if (size <= 3584-1-0)
				return 32;
		case 51:
			if (size <= 4096-1-0)
				return 33;
			if (size <= 4112-1-0)
				return 34;
			if (size <= 5120-1-0)
				return 35;
			if (size <= 6144-1-0)
				return 36;
			if (size <= 7168-1-0)
				return 37;
		case 50:
			if (size <= 8192-1-0)
				return 38;
			if (size <= 8208-1-0)
				return 39;
			if (size <= 10240-1-0)
				return 40;
			if (size <= 12288-1-0)
				return 41;
		case 49:
			if (size <= 16384-1-0)
				return 42;
		case 48:
			if (size <= 32768-1-0)
				return 43;
		case 47:
			if (size <= 65536-1-0)
				return 44;
		case 46:
			if (size <= 131072-1-0)
				return 45;
		case 45:
			if (size <= 262144-1-0)
				return 46;
		case 44:
			if (size <= 524288-1-0)
				return 47;
		case 43:
			if (size <= 1048576-1-0)
				return 48;
		case 42:
			if (size <= 2097152-1-0)
				return 49;
		case 41:
			if (size <= 4194304-1-0)
				return 50;
		case 40:
			if (size <= 8388608-1-0)
				return 51;
		case 39:
			if (size <= 16777216-1-1)
				return 52;
		case 38:
			if (size <= 33554432-1-3)
				return 53;
		case 37:
			if (size <= 67108864-1-6)
				return 54;
		case 36:
			if (size <= 134217728-1-14)
				return 55;
		case 35:
			if (size <= 268435456-1-28)
				return 56;
		case 34:
			if (size <= 536870912-1-58)
				return 57;
		case 33:
			if (size <= 1073741824-1-118)
				return 58;
		case 32:
			if (size <= 2147483648-1-240)
				return 59;
		case 31:
			if (size <= 4294967296-1-488)
				return 60;
		case 30:
			if (size <= 8589934592-1-995)
				return 61;
		case 29:
		case 28:
		case 27:
		case 26:
		case 25:
		case 24:
		case 23:
		case 22:
		case 21:
		case 20:
		case 19:
		case 18:
		case 17:
		case 16:
		case 15:
		case 14:
		case 13:
		case 12:
		case 11:
		case 10:
		case 9:
		case 8:
		case 7:
		case 6:
		case 5:
		case 4:
		case 3:
		case 2:
		case 1:
		case 0:
		default:
			return 0;
	}
}

