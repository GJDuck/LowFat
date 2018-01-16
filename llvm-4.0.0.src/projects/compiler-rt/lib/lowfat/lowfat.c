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
#include <string.h>

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef F_SETLEASE
#define F_SETLEASE              1024
#endif

#define LOWFAT_PAGE_SIZE        4096
#define LOWFAT_MAX_ADDRESS      0x1000000000000ull

#define LOWFAT_CONSTRUCTOR      __attribute__((__constructor__(10102)))
#define LOWFAT_DESTRUCTOR       __attribute__((__destructor__(10102)))
#define LOWFAT_NOINLINE         __attribute__((__noinline__))
#define LOWFAT_NORETURN         __attribute__((__noreturn__))
#define LOWFAT_CONST            __attribute__((__const__))
#define LOWFAT_ALIAS(name)      __attribute__((__alias__(name)))
#define LOWFAT_DATA             /* EMPTY */
#define LOWFAT_CPUID(a, c, ax, bx, cx, dx)                                  \
    __asm__ __volatile__ ("cpuid" : "=a" (ax), "=b" (bx), "=c" (cx),        \
        "=d" (dx) : "a" (a), "c" (c))

#include "lowfat.h"

#define LOWFAT_SIZES            _LOWFAT_SIZES
#define LOWFAT_MAGICS           _LOWFAT_MAGICS

static LOWFAT_NOINLINE void lowfat_rand(void *buf, size_t len);
static int lowfat_create_shm(size_t size);
static LOWFAT_CONST void *lowfat_region(size_t idx);
extern LOWFAT_CONST void *lowfat_stack_mirror(void *ptr, size_t idx);
extern LOWFAT_NOINLINE void lowfat_stack_pivot(void);
static LOWFAT_NOINLINE LOWFAT_NORETURN void lowfat_error(
    const char *format, ...);
static LOWFAT_NOINLINE void lowfat_warning(const char *format, ...);

#include "lowfat_config.c"

static LOWFAT_DATA uint8_t *lowfat_seed = NULL;
static LOWFAT_DATA size_t lowfat_seed_pos = LOWFAT_PAGE_SIZE;

#ifndef LOWFAT_DATA_ONLY
#include "lowfat_threads.c"
#include "lowfat_malloc.c"
#include "lowfat_memops.c"
#ifndef LOWFAT_NO_MEMORY_ALIAS
#include "lowfat_fork.c"
#endif
#endif

static LOWFAT_DATA lowfat_mutex_t lowfat_print_mutex;
static LOWFAT_DATA size_t lowfat_num_messages = 0;
static LOWFAT_DATA bool lowfat_malloc_inited = false;

extern size_t lowfat_get_num_errors(void)
{
    return lowfat_num_messages;
}

/*
 * CSPRNG
 */
static LOWFAT_NOINLINE void lowfat_rand(void *buf0, size_t len)
{
    uint8_t *buf = (uint8_t *)buf0;
    while (len > 0)
    {
        if (lowfat_seed_pos >= LOWFAT_PAGE_SIZE)
        {
            const char *path = "/dev/urandom";
            int fd = open(path, O_RDONLY);
            if (fd < 0)
                lowfat_error("failed to open \"%s\": %s", path,
                    strerror(errno));
            ssize_t r = read(fd, lowfat_seed, LOWFAT_PAGE_SIZE);
            if (r < 0)
                lowfat_error("failed to read \"%s\": %s", path,
                    strerror(errno));
            if (r != LOWFAT_PAGE_SIZE)
                lowfat_error("failed to read %zu bytes from \"%s\"",
                    LOWFAT_PAGE_SIZE, path);
            if (close(fd) < 0)
                lowfat_error("failed to close \"%s\": %s", path,
                    strerror(errno));
            lowfat_seed_pos = 0;
        }
        *buf = lowfat_seed[lowfat_seed_pos];
        lowfat_seed[lowfat_seed_pos] = 0;
        lowfat_seed_pos++;
        len--;
        buf++;
    }
}

extern LOWFAT_NOINLINE const char *lowfat_color_escape_code(FILE *stream,
    bool red)
{
    // Simply assumes ANSI compatible terminal rather than create ncurses
    // dependency.  Who still uses non-ANSI terminals anyway?
    int err = errno;
    int r = isatty(fileno(stream));
    errno = err;
    if (!r)
        return "";
    else
        return (red? "\33[31m": "\33[0m");
}

/*
 * Print the lowfat banner.
 */
static LOWFAT_NOINLINE void lowfat_print_banner(void)
{
    fprintf(stderr, "%s"
        "_|                                      _|_|_|_|            _|\n"
        "_|          _|_|    _|      _|      _|  _|        _|_|_|  _|_|_|_|\n"
        "_|        _|    _|  _|      _|      _|  _|_|_|  _|    _|    _|\n"
        "_|        _|    _|    _|  _|  _|  _|    _|      _|    _|    _|\n"
        "_|_|_|_|    _|_|        _|      _|      _|        _|_|_|      _|_|%s\n"
        "\n",
        lowfat_color_escape_code(stderr, true),
        lowfat_color_escape_code(stderr, false));
}

/*
 * Print an error or warning.
 */
#include <execinfo.h>
static LOWFAT_NOINLINE void lowfat_message(const char *format, bool err,
    va_list ap)
{
    lowfat_mutex_lock(&lowfat_print_mutex);

    // (1) Print the error:
    lowfat_print_banner();
    fprintf(stderr, "%sLOWFAT %s%s: ",
        lowfat_color_escape_code(stderr, true),
        (err? "ERROR": "WARNING"),
        lowfat_color_escape_code(stderr, false));
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);

    // (2) Dump the stack:
    if (lowfat_malloc_inited)
    {
        size_t MAX_TRACE = 256;
        void *trace[MAX_TRACE];
        int len = backtrace(trace, sizeof(trace) / sizeof(void *));
        char **trace_strs = backtrace_symbols(trace, len);
        for (int i = 0; i < len; i++)
            fprintf(stderr, "%d: %s\n", i, trace_strs[i]);
        if (len == 0 || len == sizeof(trace) / sizeof(void *))
            fprintf(stderr, "...\n");
    }

    lowfat_num_messages++;
    lowfat_mutex_unlock(&lowfat_print_mutex);
}

/*
 * Print an error and exit.
 */
static LOWFAT_NOINLINE LOWFAT_NORETURN void lowfat_error(
    const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    lowfat_message(format, /*err=*/true, ap);
    va_end(ap);
    abort();
}

/*
 * Print a warning.
 */
static LOWFAT_NOINLINE void lowfat_warning(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    lowfat_message(format, /*err=*/false, ap);
    va_end(ap);
}

/*
 * Open a unique+anonymous shared memory object.
 */
static int lowfat_create_shm(size_t size)
{
    char path[] =
        "/dev/shm/lowfat.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.tmp";
    for (size_t i = 0; i < sizeof(path)-2; i++)
    {
        if (path[i] != 'X' || path[i+1] != 'X')
            continue;
        const char *xdigs = "0123456789ABCDEF";
        uint8_t rbyte;
        lowfat_rand(&rbyte, sizeof(rbyte));
        path[i++] = xdigs[rbyte & 0x0F];
        path[i]   = xdigs[(rbyte >> 4) & 0x0F];
    }
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0);
    if (fd < 0)
        lowfat_error("failed to open \"%s\": %s", path, strerror(errno));
    if (unlink(path) < 0)
        lowfat_error("failed to unlink \"%s\": %s", path, strerror(errno));
    // The following call will fail if:
    // (1) fd is not "the" unique file descriptor to `path'; or
    // (2) a hardlink to `path' exists.
    if (fcntl(fd, F_SETLEASE, F_WRLCK) < 0)
        lowfat_error("failed to lease \"%s\": %s", path, strerror(errno));
    if (ftruncate(fd, size) < 0)
        lowfat_error("failed to truncate \"%s\": %s\n", path, strerror(errno));
    return fd;
}

/*
 * Get pointer kind as a string.
 */
static LOWFAT_NOINLINE const char *lowfat_kind(const void *ptr)
{
    if (!lowfat_is_ptr(ptr))
        return "nonfat";
    if (lowfat_is_heap_ptr(ptr))
        return "heap";
    if (lowfat_is_stack_ptr(ptr))
        return "stack";
    if (lowfat_is_global_ptr(ptr))
        return "global";
    return "unused";
}

/*
 * LOWFAT SEGV handler.
 */
static LOWFAT_NORETURN void lowfat_segv_handler(int sig, siginfo_t *info,
    void *context0)
{
    void *ptr = info->si_addr;
    lowfat_error("caught deadly SEGV signal\n"
        "\tpointer = %p (%s)\n"
        "\tbase    = %p\n"
        "\tsize    = %zu",
        ptr, lowfat_kind(ptr), lowfat_base(ptr), lowfat_size(ptr));
}

/*
 * Setup the LOWFAT environment.
 */
void LOWFAT_CONSTRUCTOR lowfat_init(void)
{
    static bool lowfat_inited = false;
    if (lowfat_inited)
        return;
    lowfat_inited = true;

    lowfat_mutex_init(&lowfat_print_mutex);

    // Basic sanity checks:
    if (sizeof(void *) != sizeof(uint64_t))
        lowfat_error("incompatible architecture (not x86-64)");
    if (sysconf(_SC_PAGESIZE) != LOWFAT_PAGE_SIZE)
        lowfat_error("incompatible system page size (expected %u; got %ld)",
            LOWFAT_PAGE_SIZE, sysconf(_SC_PAGESIZE));
#ifndef LOWFAT_LEGACY
    uint32_t eax, ebx, ecx, edx;
    LOWFAT_CPUID(7, 0, eax, ebx, ecx, edx);
    if (((ebx >> 3) & 1) == 0 || ((ebx >> 8) & 1) == 0)
        lowfat_error("incompatible architecture (no BMI/BMI2 support)");
#endif
 
    // Random seed memory:
    lowfat_seed = (uint8_t *)mmap(NULL, LOWFAT_PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (lowfat_seed == MAP_FAILED)
        lowfat_error("failed to allocate random seed: %s", strerror(errno));

    // Init LOWFAT_SIZES and LOWFAT_MAGICS
    {
        // Create LOWFAT_SIZES:
        size_t total_pages = (LOWFAT_MAX_ADDRESS / LOWFAT_REGION_SIZE) /
            (LOWFAT_PAGE_SIZE / sizeof(size_t));
        int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED;
        int prot = PROT_READ | PROT_WRITE;
        size_t len = LOWFAT_SIZES_PAGES * LOWFAT_PAGE_SIZE;
        void *ptr = mmap((void *)LOWFAT_SIZES, len, prot, flags, -1, 0);
        if (ptr != (void *)LOWFAT_SIZES)
        {
            mmap_error:
            lowfat_error("failed to mmap memory: %s", strerror(errno));
        }
        int fd = lowfat_create_shm(LOWFAT_PAGE_SIZE);
        void *start = (uint8_t *)LOWFAT_SIZES + len;
        void *end = (uint8_t *)LOWFAT_SIZES + total_pages * LOWFAT_PAGE_SIZE;
        while (start < end)
        {
            flags = MAP_SHARED | MAP_NORESERVE | MAP_FIXED;
            ptr = mmap(start, LOWFAT_PAGE_SIZE, prot, flags, fd, 0);
            if (ptr != start)
                goto mmap_error;
            start = (uint8_t *)start + LOWFAT_PAGE_SIZE;
            prot = PROT_READ;
        }
        if (close(fd) < 0)
        {
            close_error:
            lowfat_error("failed to close object: %s", strerror(errno));
        }

        // Create LOWFAT_MAGICS:
        flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED;
        prot = PROT_READ | PROT_WRITE;
        ptr = mmap((void *)LOWFAT_MAGICS, len, prot, flags, -1, 0);
        if (ptr != (void *)LOWFAT_MAGICS)
            goto mmap_error;
        prot = PROT_READ;
        len = (total_pages - LOWFAT_SIZES_PAGES) * LOWFAT_PAGE_SIZE;
        start = (uint8_t *)LOWFAT_MAGICS +
            LOWFAT_SIZES_PAGES * LOWFAT_PAGE_SIZE;
        ptr = mmap(start, len, prot, flags, -1, 0);
        if (ptr != start)
            goto mmap_error;

        // Init LOWFAT_SIZES and LOWFAT_MAGICS data:
        size_t i = 0;
        LOWFAT_SIZES[i++] = SIZE_MAX;
        size_t sizes_len = sizeof(lowfat_sizes) / sizeof(lowfat_sizes[0]);
        for (size_t j = 0; j < sizes_len; j++)
            LOWFAT_SIZES[i++] = lowfat_sizes[j];
        while (((uintptr_t)(LOWFAT_SIZES + i) % LOWFAT_PAGE_SIZE) != 0)
            LOWFAT_SIZES[i++] = SIZE_MAX;
        for (size_t j = 0; j < LOWFAT_PAGE_SIZE / sizeof(size_t); j++)
            LOWFAT_SIZES[i++] = SIZE_MAX;
        i = 0;
        LOWFAT_MAGICS[i++] = 0;
        for (size_t j = 0; j < sizes_len; j++)
            LOWFAT_MAGICS[i++] = lowfat_magics[j];
        while (((uintptr_t)(LOWFAT_MAGICS + i) % LOWFAT_PAGE_SIZE) != 0)
            LOWFAT_MAGICS[i++] = 0;

        len = (LOWFAT_SIZES_PAGES + 1) * LOWFAT_PAGE_SIZE;
        if (mprotect((void *)LOWFAT_SIZES, len, PROT_READ) < 0 ||
            mprotect((void *)LOWFAT_MAGICS, LOWFAT_SIZES_PAGES *
                LOWFAT_PAGE_SIZE, PROT_READ) < 0)
            lowfat_error("failed to write protect memory: %s",
                strerror(errno));
    }

#ifndef LOWFAT_DATA_ONLY

    // Init regions for lowfat_malloc()
    for (size_t i = 1; i <= LOWFAT_NUM_REGIONS; i++)
    {
        const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE |
            MAP_FIXED;
        const int prot = PROT_NONE;
        void *heap_start = (uint8_t *)lowfat_region(i) +
            LOWFAT_HEAP_MEMORY_OFFSET;
        void *ptr = mmap(heap_start, LOWFAT_HEAP_MEMORY_SIZE, prot, flags,
            -1, 0);
        if (ptr != heap_start)
            goto mmap_error;
    }

    // Init regions for the stack
#ifndef LOWFAT_NO_MEMORY_ALIAS
    {
        int fd = lowfat_create_shm(LOWFAT_STACK_MEMORY_SIZE);
        size_t idx;
        for (size_t i = 0; (idx = lowfat_stacks[i]) != 0; i++)
        {
            int flags = MAP_FIXED | MAP_NORESERVE | MAP_SHARED;
            const int prot = PROT_NONE;
            void *stack_start = (uint8_t *)lowfat_region(idx) +
                LOWFAT_STACK_MEMORY_OFFSET;
            void *ptr = mmap(stack_start, LOWFAT_STACK_MEMORY_SIZE, prot,
                flags, fd, 0);
            if (ptr != stack_start)
                goto mmap_error;
        }
        if (close(fd) < 0)
            goto close_error;
    }
#else
    size_t idx;
    for (size_t i = 0; (idx = lowfat_stacks[i]) != 0; i++)
    {
        int flags = MAP_FIXED | MAP_NORESERVE | MAP_ANONYMOUS | MAP_PRIVATE;
        const int prot = PROT_NONE;
        void *stack_start = (uint8_t *)lowfat_region(idx) +
            LOWFAT_STACK_MEMORY_OFFSET;
        void *ptr = mmap(stack_start, LOWFAT_STACK_MEMORY_SIZE, prot, flags,
            -1, 0);
        if (ptr != stack_start)
            goto mmap_error;
    }
#endif /* LOWFAT_NO_MEMORY_ALIAS */

    // Initialize malloc()
    if (!lowfat_malloc_init())
        lowfat_error("failed to initialize lowfat malloc(): %s",
            strerror(errno));
    lowfat_malloc_inited = true;

    // Initialize multi-threading
    if (!lowfat_threads_init())
        lowfat_error("failed to initialize lowfat threads: %s",
            strerror(errno));
    
    // Install SEGV handler.
    stack_t ss;
    ss.ss_sp = (uint8_t *)LOWFAT_PAGES_BASE((void *)&ss) -
        10 * LOWFAT_PAGE_SIZE - SIGSTKSZ;
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1)
        lowfat_error("failed to set signal stack: %s", strerror(errno));

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = lowfat_segv_handler;
    action.sa_flags |= SA_ONSTACK;
    sigaction(SIGSEGV, &action, NULL);

    // Replace stack with LOWFAT stack.
    lowfat_stack_pivot();

#endif /* LOWFAT_DATA_ONLY */
}

extern inline size_t lowfat_index(const void *ptr);
extern inline size_t lowfat_size(const void *ptr);
extern inline size_t lowfat_buffer_size(const void *ptr);

static LOWFAT_CONST void *lowfat_region(size_t idx)
{
    return (void *)(idx * LOWFAT_REGION_SIZE);
}

extern LOWFAT_CONST void *lowfat_stack_mirror(void *ptr, size_t idx)
{
    return (void *)((uintptr_t)ptr + lowfat_stack_offsets[idx]);
}

extern LOWFAT_CONST void *lowfat_stack_align(void *ptr, size_t idx)
{
    return (void *)((uintptr_t)ptr & lowfat_stack_masks[idx]);
}

extern LOWFAT_CONST size_t lowfat_stack_allocsize(size_t idx)
{
    return lowfat_stack_sizes[idx];
}

extern LOWFAT_CONST bool lowfat_is_ptr(const void *ptr)
{
    size_t idx = lowfat_index(ptr);
    return (idx - 1) <= LOWFAT_NUM_REGIONS;
}

extern LOWFAT_CONST bool lowfat_is_stack_ptr(const void *ptr)
{
    size_t idx = lowfat_index(ptr);
    uintptr_t stack_end = (uintptr_t)lowfat_region(idx) +
        LOWFAT_STACK_MEMORY_OFFSET + LOWFAT_STACK_MEMORY_SIZE;
    return lowfat_is_ptr(ptr) &&
        ((stack_end - (uintptr_t)ptr) <= LOWFAT_STACK_MEMORY_SIZE);
}

extern LOWFAT_CONST bool lowfat_is_global_ptr(const void *ptr)
{
    size_t idx = lowfat_index(ptr);
    uintptr_t global_end = (uintptr_t)lowfat_region(idx) +
        LOWFAT_GLOBAL_MEMORY_OFFSET + LOWFAT_GLOBAL_MEMORY_SIZE;
    return lowfat_is_ptr(ptr) &&
        ((global_end - (uintptr_t)ptr) <= LOWFAT_GLOBAL_MEMORY_SIZE);
}

extern LOWFAT_CONST bool lowfat_is_heap_ptr(const void *ptr)
{
    size_t idx = lowfat_index(ptr);
    uintptr_t heap_end = (uintptr_t)lowfat_region(idx) +
        LOWFAT_HEAP_MEMORY_OFFSET + LOWFAT_HEAP_MEMORY_SIZE;
    return lowfat_is_ptr(ptr) &&
        ((heap_end - (uintptr_t)ptr) <= LOWFAT_HEAP_MEMORY_SIZE);
}

static LOWFAT_NOINLINE const char *lowfat_error_kind(unsigned info)
{
    switch (info)
    {
        case LOWFAT_OOB_ERROR_READ:
            return "read";
        case LOWFAT_OOB_ERROR_WRITE:
            return "write";
        case LOWFAT_OOB_ERROR_MEMCPY:
            return "memcpy";
        case LOWFAT_OOB_ERROR_MEMSET:
            return "memset";
        case LOWFAT_OOB_ERROR_ESCAPE_CALL:
            return "escape (call)";
        case LOWFAT_OOB_ERROR_ESCAPE_RETURN:
            return "escape (return)";
        case LOWFAT_OOB_ERROR_ESCAPE_STORE:
            return "escape (store)";
        case LOWFAT_OOB_ERROR_ESCAPE_PTR2INT:
            return "escape (ptr2int)";
        case LOWFAT_OOB_ERROR_ESCAPE_INSERT:
            return "escape (insert)";
        default:
            return "unknown";
    }
}

extern LOWFAT_NORETURN void lowfat_oob_error(unsigned info,
    const void *ptr, const void *baseptr)
{
    const char *kind = lowfat_error_kind(info);
    ssize_t overflow = (ssize_t)ptr - (ssize_t)baseptr;
    if (overflow > 0)
        overflow -= lowfat_size(baseptr);
    lowfat_error(
        "out-of-bounds error detected!\n"
        "\toperation = %s\n"
        "\tpointer   = %p (%s)\n"
        "\tbase      = %p\n"
        "\tsize      = %zu\n"
        "\t%s = %+zd\n",
        kind, ptr, lowfat_kind(ptr), baseptr, lowfat_size(baseptr),
        (overflow < 0? "underflow": "overflow "), overflow);
}

extern void lowfat_oob_warning(unsigned info,
    const void *ptr, const void *baseptr)
{
    const char *kind = lowfat_error_kind(info);
    ssize_t overflow = (ssize_t)ptr - (ssize_t)baseptr;
    if (overflow > 0)
        overflow -= lowfat_size(baseptr);
    lowfat_warning(
        "out-of-bounds error detected!\n"
        "\toperation = %s\n"
        "\tpointer   = %p (%s)\n"
        "\tbase      = %p\n"
        "\tsize      = %zu\n"
        "\t%s = %+zd\n",
        kind, ptr, lowfat_kind(ptr), baseptr, lowfat_size(baseptr),
        (overflow < 0? "underflow": "overflow "), overflow);
}

extern void lowfat_oob_check(unsigned info, const void *ptr, size_t size0,
    const void *baseptr)
{
    size_t size = lowfat_size(baseptr);
    size_t diff = (size_t)((const uint8_t *)ptr - (const uint8_t *)baseptr);
    size -= size0;
    if (diff >= size)
        lowfat_oob_error(info, ptr, baseptr);
}

#ifndef LOWFAT_DATA_ONLY
/*
 * Perform a "stack pivot"; replacing the stack with the LOWFAT stack.
 * Unfortunately there is no way in Linux to specify the location of the stack
 * before the program starts up, hence the need for some hacks.
 * This code is likely fragile & non-portable.
 */
extern LOWFAT_NOINLINE void *lowfat_stack_pivot_2(void *fptr0)
{
    uint8_t *fptr = (uint8_t *)fptr0 - ((uintptr_t)fptr0 % LOWFAT_PAGE_SIZE);
    fptr += LOWFAT_PAGE_SIZE;

    // mincore() will fail with ENOMEM for unmapped pages.  We can therefore
    // linearly scan to the base of the stack.
    // Note in practice this seems to be 1-3 pages at most if called from a
    // constructor.
    unsigned char vec;
    while (mincore(fptr, LOWFAT_PAGE_SIZE, &vec) == 0)
        fptr += LOWFAT_PAGE_SIZE;
    if (errno != ENOMEM)
        lowfat_error("failed to mincore page: %s", strerror(errno));
    size_t size = fptr - (uint8_t *)fptr0;
    uint8_t *stack_base = (uint8_t *)lowfat_stack_alloc();
    if (stack_base == NULL)
        lowfat_error("failed to allocate stack: %s", strerror(errno));
    stack_base += LOWFAT_STACK_SIZE;
    memcpy(stack_base - size, fptr0, size);

    // In some cases the old stack value may be stored on the stack itself,
    // and restored later.  To fix this we search for and replace old
    // stack pointers stored on the the stack itself.  There is a small
    // chance that we may patch an unrelated value.
    void *old_stack_lo = fptr0, *old_stack_hi = fptr;
    void **new_stack_lo = (void **)(stack_base - size),
         **new_stack_hi = (void **)stack_base;
    for (void **pptr = new_stack_lo; pptr < new_stack_hi; pptr++)
    {
        void *ptr = *pptr;
        if (ptr >= old_stack_lo && ptr <= old_stack_hi)
        {
            ssize_t diff = ((uint8_t *)ptr - (uint8_t *)old_stack_lo);
            void *new_ptr = (uint8_t *)new_stack_lo + diff;
            // fprintf(stderr, "patch [%p -> %p]\n", ptr, new_ptr);
            *pptr = new_ptr;
        }
    }

    return stack_base - size;
}

__asm__ (
    "\t.align 16, 0x90\n"
    "\t.type lowfat_stack_pivot,@function\n"
    "lowfat_stack_pivot:\n"
    "\tmovq %rsp, %rdi\n"
    "\tmovabsq $lowfat_stack_pivot_2, %rax\n"
    "\tcallq *%rax\n"
    "\tmovq %rax, %rsp\n"
    "\tretq\n"
);

/*
 * This bit of magic ensures lowfat_init() is called very early in process
 * startup.  Using the "constructor" attribute is not good enough since shared
 * object constructors/initializers may be called before lowfat_init().
 */
__attribute__((section(".preinit_array"), used))
void (*__local_effective_preinit)(void) = lowfat_init;

#endif

