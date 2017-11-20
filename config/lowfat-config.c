/*
 *   _|                                      _|_|_|_|            _|
 *   _|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|
 *   _|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|
 *   _|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|
 *   _|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|
 * 
 * Gregory J. Duck.
 *
 * Copyright (c) 2017 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

#include <pthread.h>

#include <elf.h>

#define PAGE_SIZE               4096
#define MIN_SIZES               8
#define MAX_SIZES               4096
#define MIN_SIZE                16
#define MIN_REGION_SIZE         16
#define MAX_REGION_SIZE         1024
#define MB                      0x100000ul
#define GB                      0x40000000ul
#define MAX(a, b)               ((a) > (b)? (a): (b))
#define MIN(a, b)               ((a) > (b)? (b): (a))
#define STACK_SIZE              (64 * MB)
#define MAX_STACK_ALLOC         (STACK_SIZE / 2)
#define MAX_GLOBAL_ALLOC        (64 * MB)
#define ASLR_MASK               0xFFFFFFFF
#define LOWFAT_SIZES            0x200000
#define LOWFAT_MAGICS           0x300000
#define CPUID(a, c, ax, bx, cx, dx)                                         \
    __asm__ __volatile__ ("cpuid" : "=a" (ax), "=b" (bx), "=c" (cx),        \
        "=d" (dx) : "a" (a), "c" (c))

#define REGION(idx, size)       ((void *)(((idx)+1)*(size)))

static bool is_pow2(size_t x)
{
    return ((x & (x - 1)) == 0);
}

static inline uintptr_t base(uintptr_t ptr, size_t size, size_t magic)
{
    return (uintptr_t)(((__int128)ptr * (__int128)magic) >> 64) * size;
}

static int clzll(uint64_t x)
{
    if (x == 0)
        return 64;
    uint64_t bit = (uint64_t)1 << 63;
    int count = 0;
    while ((x & bit) == 0)
    {
        count++;
        bit >>= 1;
    }
    return count;
}

struct error_info
{
    pthread_mutex_t *lock;
    size_t *sizes;
    size_t *magics;
    size_t *errors;
    size_t sizes_len;
    size_t region_size;
};

/*
 * Calculate precision errors.  See:
 * "Heap Bounds Protection with Low Fat Pointers", Section 5.1.1
 */
static void *error_worker(void *arg)
{
    struct error_info *info = (struct error_info *)arg;
    pthread_mutex_t *lock = info->lock;
    size_t *sizes = info->sizes;
    size_t *magics = info->magics;
    size_t *errors = info->errors;
    size_t sizes_len = info->sizes_len;
    size_t region_size = info->region_size;
    free(info);

    pthread_mutex_lock(lock);
    for (size_t i = 0; i < sizes_len; i++)
    {
        if (errors[i] != SIZE_MAX)
            continue;
        errors[i] = 0;

        // Check for cached value:
        FILE *stream = fopen("lowfat.errs", "r");
        if (stream != NULL)
        {
            uintptr_t region_start = (i + 1) * region_size;
            void *ptr;
            size_t region_size0, size, error;
            bool found = false;
            while (fscanf(stream, "%p %zu %zu %zu", &ptr, &region_size0,
                    &size, &error) == 4)
            {
                if (region_size0 == region_size && size == sizes[i] &&
                        ptr == (void *)region_start)
                {
                    found = true;
                    break;
                }
            }
            fclose(stream);
            if (found)
            {
                errors[i] = error;
                continue;
            }
        }

        pthread_mutex_unlock(lock);

        size_t size = sizes[i];
        size_t magic = magics[i];
        uintptr_t region_start = (i + 1) * region_size;
        uintptr_t region_end = region_start + region_size;
        region_start = region_start - (region_start % size);
        size_t error = 0;
        for (uintptr_t ptr = region_start; ptr <= region_end; ptr += size)
        {
            size_t lo = 0, hi = size;
            while (lo <= hi)
            {
                size_t mid = (lo + hi) / 2;
                uintptr_t bptr = base(ptr + mid, size, magic);
                if (bptr != ptr)
                    hi = mid-1;
                else
                    lo = mid+1;
            }
            error = MAX(size - lo, error);
        }
        errors[i] = error;
        pthread_mutex_lock(lock);

        // Write value to cache:
        stream = fopen("lowfat.errs", "a");
        if (stream != NULL)
        {
            region_start = (i + 1) * region_size;
            fprintf(stream, "%p %zu %zu %zu\n", (void *)region_start,
                region_size, size, error);
            fclose(stream);
        }
    }
    pthread_mutex_unlock(lock);

    return NULL;
}

static void spawn_error_worker(pthread_t *thread, pthread_mutex_t *lock,
    size_t *sizes, size_t *magics, size_t *errors, size_t sizes_len,
    size_t region_size)
{
    struct error_info *info = (struct error_info *)malloc(
        sizeof(struct error_info));
    if (info == NULL)
    {
        fprintf(stderr, "error: failed to allocate memory: %s\n",
            strerror(errno));
        exit(EXIT_FAILURE);
    }
    info->lock = lock;
    info->sizes = sizes;
    info->magics = magics;
    info->errors = errors;
    info->sizes_len = sizes_len;
    info->region_size = region_size;
    int r = pthread_create(thread, NULL, error_worker, info);
    if (r < 0)
    {
        fprintf(stderr, "error: failed to spawn error worker: %s\n",
            strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void compile(FILE *stream, FILE *hdr_stream, FILE *ld_stream,
    size_t *sizes, size_t *magics, size_t *errors, size_t region_size,
    size_t sizes_len, bool pow2, bool legacy);

#define OPTION_NO_ERROR_GEN             1
#define OPTION_NO_MEMORY_ALIAS          2
#define OPTION_NO_REPLACE_STD_MALLOC    3
#define OPTION_NO_STD_MALLOC_FALLBACK   4
#define OPTION_NO_THREADS               5

static bool option_no_error_gen = false;
static bool option_no_memory_alias = false;
static bool option_no_std_malloc_fallback = false;
static bool option_no_replace_std_malloc = false;
static bool option_no_threads = false;

/*
 * Main.
 */
int main(int argc, char **argv)
{
    static struct option long_options[] =
    {
        {"no-error-gen",           0, 0, OPTION_NO_ERROR_GEN},
        {"no-memory-alias",        0, 0, OPTION_NO_MEMORY_ALIAS},
        {"no-replace-std-malloc",  0, 0, OPTION_NO_REPLACE_STD_MALLOC},
        {"no-std-malloc-fallback", 0, 0, OPTION_NO_STD_MALLOC_FALLBACK},
        {"no-threads",             0, 0, OPTION_NO_THREADS},
        {NULL, 0, 0, 0}
    };
    while (true)
    {
        int idx;
        int opt = getopt_long(argc, argv, "", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_NO_ERROR_GEN:
                option_no_error_gen = true;
                break;
            case OPTION_NO_MEMORY_ALIAS:
                option_no_memory_alias = true;
                break;
            case OPTION_NO_STD_MALLOC_FALLBACK:
                option_no_std_malloc_fallback = true;
                break;
            case OPTION_NO_REPLACE_STD_MALLOC:
                option_no_replace_std_malloc = true;
                break;
            case OPTION_NO_THREADS:
                option_no_threads = true;
                break;
            default:
            usage:
                fprintf(stderr, "usage: %s [OPTIONS] sizes.cfg "
                    "region-size\n\n", argv[0]);
                fprintf(stderr, "Where OPTIONS are:\n");
                fprintf(stderr, "\t--no-error-gen\n");
                fprintf(stderr, "\t\tSkip error generation (may produce "
                    "invalid results).\n");
                fprintf(stderr, "\t--no-memory-alias\n");
                fprintf(stderr, "\t\tDo not use memory aliasing for the "
                    "stack.\n");
                fprintf(stderr, "\t--no-replace-std-malloc\n");
                fprintf(stderr, "\t\tDo not replace stdlib malloc() with "
                    "low-fat malloc() in\n");
                fprintf(stderr, "\t\tuninstrumented (linked) code.  NOTE: "
                    "stdlib malloc() will\n");
                fprintf(stderr, "\t\tstill be replaced in instrumented "
                    "code.\n");
                fprintf(stderr, "\t--no-std-malloc-fallback\n");
                fprintf(stderr, "\t\tNever fallback to stdlib malloc() if "
                    "low-fat malloc() fails.\n");
                fprintf(stderr, "\t--no-threads\n");
                fprintf(stderr, "\t\tDo not support multi-threaded "
                    "programs.\n");
                return EXIT_FAILURE;
        }
    }
    if (optind != argc-2)
        goto usage;

    printf(
        "_|                                      _|_|_|_|            _|\n"
        "_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|\n"
        "_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|\n"
        "_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|\n"
        "_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|\n"
        "\n");

    size_t region_size = atoi(argv[optind+1]);
    if (region_size < MIN_REGION_SIZE || region_size > MAX_REGION_SIZE)
    {
        fprintf(stderr, "error: region size must be within range %u..%uGB\n",
            MIN_REGION_SIZE, MAX_REGION_SIZE);
        return EXIT_FAILURE;
    }
    if (!is_pow2(region_size))
    {
        fprintf(stderr, "error: region size must be a power-of-two\n");
        return EXIT_FAILURE;
    }
    region_size *= GB;
    size_t MAX_SIZE = region_size / 4;

    if (PAGE_SIZE != getpagesize())
    {
        fprintf(stderr, "error: page size mis-match (expected %u, got %d)\n",
            PAGE_SIZE, getpagesize());
        return EXIT_FAILURE;
    }

    size_t sizes[MAX_SIZES];
    const char *filename = argv[optind];
    printf("Parsing \"%s\"...\n", filename);
    FILE *stream = fopen(filename, "r");
    if (stream == NULL)
    {
        fprintf(stderr, "error: failed to open file \"%s\": %s\n", filename,
            strerror(errno));
        return EXIT_FAILURE;
    }
    size_t i;
    for (i = 0; i < MAX_SIZES; i++)
    {
        if (fscanf(stream, "%zu", sizes+i) != 1)
        {
            if (ferror(stream))
            {
                read_error:
                fprintf(stderr, "error: failed to read file \"%s\": %s\n",
                    filename, strerror(errno));
                return EXIT_FAILURE;
            }
            break;
        }
        if (sizes[i] > MAX_SIZE)
            break;
        if (sizes[i] < MIN_SIZE || sizes[i] % MIN_SIZE != 0)
        {
            fprintf(stderr, "error: size %zu from size configuration file "
                "\"%s\" is invalid (min=%u, max=%zu, multiple-of-%u)\n",
                sizes[i], filename, MIN_SIZE, MAX_SIZE, MIN_SIZE);
            return EXIT_FAILURE;
        }
        if (i == 0 && sizes[i] != MIN_SIZE)
        {
            fprintf(stderr, "error: size for region #0 must be %u\n",
                MIN_SIZE);
            return EXIT_FAILURE;
        }
        if (i > 0 && sizes[i] <= sizes[i-1])
        {
            fprintf(stderr, "error: size configuration file \"%s\" is not "
                "ascending (%zu <= %zu)\n", filename, sizes[i], sizes[i-1]);
            return EXIT_FAILURE;
        }
    }
    fclose(stream);
    if (i <= MIN_SIZES || i >= MAX_SIZES)
    {
        fprintf(stderr, "error: size configuration file \"%s\" length "
            "out-of-range (min=%u, max=%u)\n", filename, MIN_SIZES+1,
            MAX_SIZES-1);
        return EXIT_FAILURE;
    }
    size_t sizes_len = i;

    // Check for LZCNT/BMI support:
    bool legacy = false;
    uint32_t eax, ebx, ecx, edx;
    CPUID(7, 0, eax, ebx, ecx, edx);
    if (((ebx >> 3) & 1) == 0 || ((ebx >> 8) & 1) == 0)
        legacy = true;

    // Check for power-of-two sizes:
    bool ispow2 = true;
    for (size_t i = 0; i < sizes_len; i++)
    {
        if (!is_pow2(sizes[i]))
        {
            ispow2 = false;
            break;
        }
    }
    printf("IsPow2=%s\n", (ispow2? "true": "false"));

    // Calculate magic numbers:
    size_t magics[sizes_len];
    if (!ispow2)
    {
        for (size_t i = 0; i < sizes_len; i++)
        {
            __int128 r = UINT64_MAX;
            r++;
            magics[i] = (size_t)(r / (__int128)sizes[i]) + 1;
            printf("Region #%zu: size=%zu magic=0x%.16zX\n", i+1, sizes[i],
                magics[i]);
        }
    }
    else
    {
        for (size_t i = 0; i < sizes_len; i++)
        {
            magics[i] = UINT64_MAX << (unsigned)log2((double)sizes[i]);
            printf("Region #%zu: size=%zu magic=0x%.16zX\n", i+1, sizes[i],
                magics[i]);
        }
    }

    // Calculate errors:
    size_t errors[sizes_len];
    memset(errors, 0, sizeof(errors));
    if (!option_no_error_gen && !ispow2)
    {
        printf("Calculating errors (this may take some time)...\n");
        unsigned NUM_WORKERS = (unsigned)sysconf(_SC_NPROCESSORS_ONLN);
        pthread_t workers[NUM_WORKERS];
        pthread_mutex_t lock;
        pthread_mutex_init(&lock, NULL);
        for (size_t i = 0; i < sizes_len; i++)
            errors[i] = SIZE_MAX;
        for (size_t i = 0; i < NUM_WORKERS; i++)
            spawn_error_worker(workers+i, &lock, sizes, magics, errors,
                sizes_len, region_size);
        for (size_t i = 0; i < NUM_WORKERS; i++)
            pthread_join(workers[i], NULL);
        for (size_t i = 0; i < sizes_len; i++)
            printf("Region #%zu: error=%zuB\n", i+1, errors[i]);
    }

    // Generate files:
    filename = "lowfat_config.c";
    printf("Generating \"%s\"...\n", filename);
    stream = fopen(filename, "w");
    if (stream == NULL)
    {
        fprintf(stderr, "error: failed to open file \"%s\": %s\n", filename,
            strerror(errno));
        return EXIT_FAILURE;
    }
    filename = "lowfat_config.h";
    FILE *hdr_stream = fopen(filename, "w");
    if (hdr_stream == NULL)
    {
        fprintf(stderr, "error: failed to open file \"%s\": %s\n", filename,
            strerror(errno));
        return EXIT_FAILURE;
    }
    filename = "lowfat.ld";
    FILE *ld_stream = fopen(filename, "w");
    if (stream == NULL)
    {
        fprintf(stderr, "error: failed to open file \"%s\": %s\n", filename,
            strerror(errno));
        return EXIT_FAILURE;
    }
    compile(stream, hdr_stream, ld_stream, sizes, magics, errors,
        region_size, sizes_len, ispow2, legacy);
    fclose(stream);
    fclose(hdr_stream);
    fclose(ld_stream);

    printf("Done...\n");
    return 0;
}

static size_t stack_select(size_t *sizes, size_t sizes_len, size_t size)
{
    if (size > MAX_STACK_ALLOC)
        return sizes_len;
    for (size_t i = 0; i < sizes_len; i++)
    {
        if (!is_pow2(sizes[i]))
            continue;
        if (size <= sizes[i])
            return i;
    }
    return sizes_len;
}

/*
 * Output the low-fat-pointer configuration for the given parameters.
 */
static void compile(FILE *stream, FILE *hdr_stream, FILE *ld_stream,
    size_t *sizes, size_t *magics, size_t *errors, size_t region_size,
    size_t sizes_len, bool pow2, bool legacy)
{
    /*
     * Region layout:
     * +------------------------------+----+----+---------+
     * | H                            | G1 | G2 | S       |
     * +------------------------------+----+----+---------+
     *
     * H = Heap memory
     * G1 = Global memory (non-const) (2GB)
     * G2 = Global memory (const) (2GB)
     * S = Stack memory (4GB)
     */
	size_t H_G1_GAP_SIZE = 8*PAGE_SIZE;
	size_t G1_G2_GAP_SIZE = 0;
	size_t G2_S_GAP_SIZE = 8*PAGE_SIZE;
	size_t S_SIZE = 4*GB;
	size_t G1_SIZE = 8*GB;
	size_t G2_SIZE = 8*GB;
	size_t H_SIZE = region_size - H_G1_GAP_SIZE - G1_SIZE - G1_G2_GAP_SIZE -
        G2_SIZE - G2_S_GAP_SIZE - S_SIZE;
    size_t H_OFFSET = 0;
    size_t G_FUDGE = PAGE_SIZE;
    size_t G1_OFFSET = H_OFFSET + H_SIZE + H_G1_GAP_SIZE - G_FUDGE;
    size_t G2_OFFSET = G1_OFFSET + G1_SIZE + G1_G2_GAP_SIZE;
    size_t S_OFFSET = G2_OFFSET + G2_SIZE + G2_S_GAP_SIZE + G_FUDGE;

    size_t stack_region = sizes_len+1;

    if (hdr_stream != NULL)
    {
        fprintf(hdr_stream, "/* AUTOMATICALLY GENERATED */\n");
        fprintf(hdr_stream, "#ifndef __LOWFAT_CONFIG_H\n");
        fprintf(hdr_stream, "#define __LOWFAT_CONFIG_H\n");
        fprintf(hdr_stream, "\n");
        fprintf(hdr_stream, "#define _LOWFAT_SIZES ((size_t *)0x%X)\n",
            LOWFAT_SIZES);
        fprintf(hdr_stream, "#define _LOWFAT_MAGICS ((uint64_t *)0x%X)\n",
            LOWFAT_MAGICS);
        fprintf(hdr_stream, "#define _LOWFAT_REGION_SIZE %zuull\n",
            region_size);
        if (legacy)
            fprintf(hdr_stream, "#define _LOWFAT_LEGACY 1\n");
        fprintf(hdr_stream, "\n");
        fprintf(hdr_stream, "#endif\t/* __LOWFAT_CONFIG_H */\n");
    }

    if (ld_stream != NULL)
    {
        fprintf(ld_stream, "/* AUTOMATICALLY GENERATED */\n");
        fprintf(ld_stream, "\n");
        fprintf(ld_stream, "SECTIONS\n");
        fprintf(ld_stream, "{\n");
        for (size_t i = 0; i < sizes_len; i++)
        {
            if (sizes[i] >= MAX_GLOBAL_ALLOC)
                break;
            if (!is_pow2(sizes[i]))
                continue;
            void *start = REGION(i, region_size) + G1_OFFSET;
            fprintf(ld_stream, "\t. = %p + SIZEOF_HEADERS;\n", start);
            fprintf(ld_stream, "\tlowfat_section_%zu :\n", sizes[i]);
            fprintf(ld_stream, "\t{\n");
            fprintf(ld_stream, "\t\tKEEP(*(lowfat_section_%zu))\n", sizes[i]);
            fprintf(ld_stream, "\t}\n");
            void *end = start + G1_SIZE;
            fprintf(ld_stream, "\tASSERT(. < %p, \"Lowfat section "
                "(lowfat_section_%zu) is too big; max size is 2GB\")\n",
                end, sizes[i]);
            start = REGION(i, region_size) + G2_OFFSET;
            fprintf(ld_stream, "\t. = %p + SIZEOF_HEADERS;\n", start);
            fprintf(ld_stream, "\tlowfat_section_const_%zu :\n", sizes[i]);
            fprintf(ld_stream, "\t{\n");
            fprintf(ld_stream, "\t\tKEEP(*(lowfat_section_const_%zu))\n",
                sizes[i]);
            fprintf(ld_stream, "\t}\n");
            end = start + G1_SIZE;
            fprintf(ld_stream, "\tASSERT(. < %p, \"Lowfat section "
                "(lowfat_const_section_%zu) is too big; max size is 2GB\")\n",
                end, sizes[i]);
        }
        const size_t data_buffer = 32;      // 32 regions
        void *data_start = REGION(sizes_len + data_buffer, region_size);
        fprintf(ld_stream, "\t. = %p + SIZEOF_HEADERS;\n", data_start);
        fprintf(ld_stream, "\tLOWFAT_DATA :\n");
        fprintf(ld_stream, "\t{\n");
        fprintf(ld_stream, "\t\tKEEP(*(LOWFAT_DATA))\n");
        fprintf(ld_stream, "\t}\n");
        void *const_data_start = REGION(sizes_len + data_buffer + 1,
            region_size);
        fprintf(ld_stream, "\t. = %p + SIZEOF_HEADERS;\n", const_data_start);
        fprintf(ld_stream, "\tLOWFAT_CONST_DATA :\n");
        fprintf(ld_stream, "\t{\n");
        fprintf(ld_stream, "\t\tKEEP(*(LOWFAT_CONST_DATA))\n");
        fprintf(ld_stream, "\t}\n");
        fprintf(ld_stream, "}\n");
        fprintf(ld_stream, "\n");
        fprintf(ld_stream, "INSERT AFTER .gnu.attributes;\n");
        fprintf(ld_stream, "\n");
    }

    fprintf(stream, "/* AUTOMATICALLY GENERATED */\n");
    fprintf(stream, "\n");
    fprintf(stream, "#include \"lowfat_config.h\"\n");
    fprintf(stream, "\n");
    fprintf(stream, "#define LOWFAT_IS_POW2 %u\n", pow2);
    fprintf(stream, "#define LOWFAT_NUM_REGIONS %zu\n", sizes_len);
    size_t num_pages = (sizes_len * sizeof(size_t) - 1) / PAGE_SIZE + 1;
    fprintf(stream, "#define LOWFAT_SIZES_PAGES %zu\n", num_pages);
    fprintf(stream, "#define LOWFAT_REGION_SIZE _LOWFAT_REGION_SIZE\n");
    size_t region_shift = (size_t)log2((double)region_size);
    fprintf(stream, "#define LOWFAT_REGION_SIZE_SHIFT %zu\n", region_shift);
    fprintf(stream, "#define LOWFAT_STACK_MEMORY_SIZE %zu\n", S_SIZE);
    fprintf(stream, "#define LOWFAT_GLOBAL_MEMORY_SIZE %zu\n",
		G1_SIZE + G2_SIZE);
    fprintf(stream, "#define LOWFAT_HEAP_MEMORY_SIZE %zu\n", H_SIZE);
	fprintf(stream, "#define LOWFAT_STACK_MEMORY_OFFSET %zu\n", S_OFFSET);
	fprintf(stream, "#define LOWFAT_GLOBAL_MEMORY_OFFSET %zu\n", G1_OFFSET);
	fprintf(stream, "#define LOWFAT_HEAP_MEMORY_OFFSET %zu\n", H_OFFSET);
    size_t stack_size = STACK_SIZE;
    fprintf(stream, "#define LOWFAT_STACK_SIZE %zu\n", stack_size);
    fprintf(stream, "#define LOWFAT_PAGE_SIZE %u\n", PAGE_SIZE);
    fprintf(stream, "#define LOWFAT_HEAP_ASLR_MASK 0x%.8X\n",
        ASLR_MASK);
    fprintf(stream, "#define LOWFAT_MAX_HEAP_ALLOC_SIZE %zu\n",
        sizes[sizes_len-1]);
    fprintf(stream, "#define LOWFAT_TID_OFFSET 0x%x\n", 0x2d0);
    fprintf(stream, "#define LOWFAT_JOINID_OFFSET 0x%x\n", 0x628);
    if (option_no_memory_alias)
        fprintf(stream, "#define LOWFAT_NO_MEMORY_ALIAS 1\n");
    if (option_no_std_malloc_fallback)
        fprintf(stream, "#define LOWFAT_NO_STD_MALLOC_FALLBACK 1\n");
    if (option_no_replace_std_malloc)
        fprintf(stream, "#define LOWFAT_NO_REPLACE_STD_MALLOC 1\n");
    if (option_no_threads)
        fprintf(stream, "#define LOWFAT_NO_THREADS 1\n");
    if (legacy)
        fprintf(stream, "#define LOWFAT_LEGACY 1\n");
    size_t max_stack_alloc = MAX_STACK_ALLOC;
    size_t max_stack_region;
    bool found = false;
    for (ssize_t i = sizes_len-1; i >= 0; i--)
    {
        if (i == 0 || (is_pow2(sizes[i]) && max_stack_alloc == sizes[i]))
        {
            found = true;
            max_stack_region = i+1;
            break;
        }
    }
    if (!found)
    {
        fprintf(stderr, "error: max stack allocation size (%zu) not found in "
            "size configuration\n", max_stack_alloc);
        exit(EXIT_FAILURE);
    }
    fprintf(stream, "#define LOWFAT_MAX_STACK_ALLOC_SIZE %zu\n",
        max_stack_alloc);
    fprintf(stream, "#define LOWFAT_MAX_GLOBAL_ALLOC_SIZE %zu\n",
        MAX_GLOBAL_ALLOC);
    fprintf(stream, "#define LOWFAT_MIN_ALLOC_SIZE %u\n", MIN_SIZE);
    fprintf(stream, "#define LOWFAT_NUM_STACK_REGIONS %zu\n",
        max_stack_region);
    fprintf(stream, "#define LOWFAT_STACK_REGION %zu\n", stack_region);
    fprintf(stream, "#define LOWFAT_CONST_DATA "
        "__attribute__((__section__(\"LOWFAT_CONST_DATA\")))\n");
    fprintf(stream, "\n");

    // lowfat_sizes
    fprintf(stream, "static const LOWFAT_CONST_DATA size_t "
        "lowfat_sizes[] =\n");
    fprintf(stream, "{\n");
    for (size_t i = 0; i < sizes_len; i++)
        fprintf(stream, "\t%zu, /* idx=%zu */\n", sizes[i], i);
    fprintf(stream, "};\n");
    fprintf(stream, "\n");

    // lowfat_magics
    fprintf(stream, "static const LOWFAT_CONST_DATA size_t "
        "lowfat_magics[] =\n");
    fprintf(stream, "{\n");
    for (size_t i = 0; i < sizes_len; i++)
        fprintf(stream, "\t0x%.16zXull, /* idx=%zu, size=%zu */\n", magics[i],
            i, sizes[i]);
    fprintf(stream, "};\n");
    fprintf(stream, "\n");

    // lowfat_stacks
    fprintf(stream, "static const LOWFAT_CONST_DATA size_t "
        "lowfat_stacks[] =\n");
    fprintf(stream, "{\n");
    for (size_t i = 0; i < sizes_len; i++)
    {
        if (!is_pow2(sizes[i]))
            continue;
        if (sizes[i] > max_stack_alloc)
            continue;
        fprintf(stream, "\t%zu,\n", i+1);
    }
    fprintf(stream, "\t%zu,\n", stack_region);
    fprintf(stream, "\t0,\n");
    fprintf(stream, "};\n");
    fprintf(stream, "\n");

    // lowfat_stack_indexes
    fprintf(stream, "const LOWFAT_CONST_DATA size_t "
        "lowfat_stack_sizes[64+1] =\n");
    fprintf(stream, "{\n");
    for (size_t i = 0; i < 65; i++)
    {
        size_t max_size = (i >= 64? 0: SIZE_MAX >> i);
        size_t idx = stack_select(sizes, sizes_len, max_size);
        if (idx == sizes_len)
            fprintf(stream, "\t0, /* idx=%zu */\n", i);
        else
            fprintf(stream, "\t%zu, /* idx=%zu */\n", sizes[idx], i);
    }
    fprintf(stream, "};\n");
    fprintf(stream, "\n");

    // lowfat_stack_masks
    fprintf(stream, "const LOWFAT_CONST_DATA size_t "
        "lowfat_stack_masks[64+1] =\n");
    fprintf(stream, "{\n");
    for (size_t i = 0; i < 65; i++)
    {
        size_t max_size = (i >= 64? 0: SIZE_MAX >> i);
        size_t idx = stack_select(sizes, sizes_len, max_size);
        if (idx == sizes_len)
            fprintf(stream, "\t0, /* idx=%zu */\n", i);
        else
        {
            size_t size = sizes[idx];
            size_t mask = ~(size - 1);
            fprintf(stream, "\t0x%.16zXull,\t/* idx=%zu, size=%zu */\n", mask,
                i, size);
        }
    }
    fprintf(stream, "};\n");
    fprintf(stream, "\n");

    // lowfat_stack_offsets
    fprintf(stream, "const LOWFAT_CONST_DATA ssize_t "
        "lowfat_stack_offsets[64+1] =\n");
    fprintf(stream, "{\n");
    for (size_t i = 0; i < 65; i++)
    {
        size_t max_size = (i >= 64? 0: SIZE_MAX >> i);
        size_t idx = stack_select(sizes, sizes_len, max_size);
        if (idx == sizes_len)
            fprintf(stream, "\t0, /* idx=%zu */\n", i);
        else
        {
            ssize_t diff = ((ssize_t)idx - (ssize_t)sizes_len) * region_size;
            fprintf(stream, "\t%zd,\t/* idx=%zu, size=%zu */\n", diff, i,
                sizes[idx]);
        }
    }
    fprintf(stream, "};\n");
    fprintf(stream, "\n");

    // lowfat_heap_select
    fprintf(stream, "static size_t lowfat_heap_select(size_t size)\n");
    fprintf(stream, "{\n");
    if (legacy)
    {
        fprintf(stream, "\tif (size == 0)\n");
        fprintf(stream, "\t\treturn 1;\n");
    }
    fprintf(stream, "\tswitch (__builtin_clzll(size))\n");
    fprintf(stream, "\t{\n");
    fprintf(stream, "\t\tcase 64:\n");
    for (ssize_t i = 64-1; i >= 0; i--)
    {
        fprintf(stream, "\t\tcase %zu:\n", i);
        for (size_t j = 0; j < sizes_len; j++)
        {
            size_t size = sizes[j];
            if (clzll(size) == i)
            {
                fprintf(stream, "\t\t\tif (size <= %zu-1-%zu)\n", size,
                    errors[j]);
                size_t idx = j+1;
                fprintf(stream, "\t\t\t\treturn %zu;\n", idx);
            }
        }
    }
    fprintf(stream, "\t\tdefault:\n");
    fprintf(stream, "\t\t\treturn 0;\n");
    fprintf(stream, "\t}\n");
    fprintf(stream, "}\n");
    fprintf(stream, "\n");
}

