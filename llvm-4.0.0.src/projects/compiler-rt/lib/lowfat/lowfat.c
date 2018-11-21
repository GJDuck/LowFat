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

#define LOWFAT_SIZES            _LOWFAT_SIZES
#define LOWFAT_MAGICS           _LOWFAT_MAGICS

static LOWFAT_NOINLINE void lowfat_rand(void *buf, size_t len);
static LOWFAT_CONST void *lowfat_region(size_t idx);
extern LOWFAT_CONST void *lowfat_stack_mirror(void *ptr, ssize_t offset);
extern LOWFAT_NOINLINE void lowfat_stack_pivot(void);
static LOWFAT_NOINLINE LOWFAT_NORETURN void lowfat_error(
    const char *format, ...);
static LOWFAT_NOINLINE void lowfat_warning(const char *format, ...);

#include "lowfat_config.c"
#include "lowfat.h"

static LOWFAT_DATA uint8_t *lowfat_seed = NULL;
static LOWFAT_DATA size_t lowfat_seed_pos = LOWFAT_PAGE_SIZE;
static LOWFAT_DATA bool lowfat_malloc_inited = false;
#ifndef LOWFAT_WINDOWS
static LOWFAT_DATA char **lowfat_envp = NULL;
#endif

#ifdef LOWFAT_WINDOWS
#include "lowfat_windows.c"
#endif

#ifdef LOWFAT_LINUX
#include "lowfat_linux.c"
#endif

#ifndef LOWFAT_DATA_ONLY
#include "lowfat_threads.c"
#include "lowfat_malloc.c"
#include "lowfat_memops.c"
#if !defined(LOWFAT_NO_MEMORY_ALIAS) && !defined(LOWFAT_STANDALONE)
#include "lowfat_fork.c"
#endif
#endif

static LOWFAT_DATA lowfat_mutex_t lowfat_print_mutex;
static LOWFAT_DATA size_t lowfat_num_messages = 0;

extern size_t lowfat_get_num_errors(void)
{
    return lowfat_num_messages;
}

/*
 * CSPRNG
 */
static void lowfat_rand(void *buf0, size_t len)
{
    uint8_t *buf = (uint8_t *)buf0;
    while (len > 0)
    {
        if (lowfat_seed_pos >= LOWFAT_PAGE_SIZE)
        {
            lowfat_random_page(lowfat_seed);
            lowfat_seed_pos = 0;
        }
        *buf = lowfat_seed[lowfat_seed_pos];
        lowfat_seed[lowfat_seed_pos] = 0;
        lowfat_seed_pos++;
        len--;
        buf++;
    }
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
        lowfat_backtrace();

    lowfat_num_messages++;
    lowfat_mutex_unlock(&lowfat_print_mutex);
}

/*
 * Print an error and exit.
 */
LOWFAT_NOINLINE LOWFAT_NORETURN void lowfat_error(const char *format, ...)
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
LOWFAT_NOINLINE void lowfat_warning(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    lowfat_message(format, /*err=*/false, ap);
    va_end(ap);
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

#if !defined(LOWFAT_WINDOWS)
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
#endif

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
#if !defined(LOWFAT_WINDOWS)
    if (sysconf(_SC_PAGESIZE) != LOWFAT_PAGE_SIZE)
        lowfat_error("incompatible system page size (expected %u; got %ld)",
            LOWFAT_PAGE_SIZE, sysconf(_SC_PAGESIZE));
#endif
#if !defined(LOWFAT_LEGACY)
    uint32_t eax, ebx, ecx, edx;
    LOWFAT_CPUID(7, 0, eax, ebx, ecx, edx);
    if (((ebx >> 3) & 1) == 0 || ((ebx >> 8) & 1) == 0)
        lowfat_error("incompatible architecture (no BMI/BMI2 support)");
#endif
 
    // Random seed memory:
    lowfat_seed = (uint8_t *)lowfat_map(NULL, LOWFAT_PAGE_SIZE, true, true, -1);
    if (lowfat_seed == NULL)
        lowfat_error("failed to allocate random seed: %s", strerror(errno));

    // Init LOWFAT_SIZES and LOWFAT_MAGICS
    {
        // Create LOWFAT_SIZES:
        size_t total_pages = (LOWFAT_MAX_ADDRESS / LOWFAT_REGION_SIZE) /
            (LOWFAT_PAGE_SIZE / sizeof(size_t));
        size_t len = total_pages * LOWFAT_PAGE_SIZE;
        void *ptr = lowfat_map((void *)LOWFAT_SIZES, len, true, true, -1);
        if (ptr != (void *)LOWFAT_SIZES)
        {
            mmap_error:
            lowfat_error("failed to mmap memory: %s", strerror(errno));
        }

#if !defined(LOWFAT_WINDOWS)
        int fd = lowfat_create_shm(LOWFAT_PAGE_SIZE);
        void *start = (uint8_t *)LOWFAT_SIZES +
            LOWFAT_SIZES_PAGES * LOWFAT_PAGE_SIZE;
        void *end = (uint8_t *)LOWFAT_SIZES + total_pages * LOWFAT_PAGE_SIZE;
        bool w = true;
        while (start < end)
        {
            ptr = lowfat_map(start, LOWFAT_PAGE_SIZE, true, w, fd);
            if (ptr != start)
                goto mmap_error;
            start = (uint8_t *)start + LOWFAT_PAGE_SIZE;
            w = false;
        }
        if (close(fd) < 0)
        {
            close_error:
            lowfat_error("failed to close object: %s", strerror(errno));
        }
        size_t size_init_len = LOWFAT_PAGE_SIZE;
#else
        size_t size_init_len =
            (total_pages - LOWFAT_SIZES_PAGES) * LOWFAT_PAGE_SIZE;
#endif

        // Create LOWFAT_MAGICS:
        ptr = lowfat_map((void *)LOWFAT_MAGICS, len, true, true, -1);
        if (ptr != (void *)LOWFAT_MAGICS)
            goto mmap_error;

        // Init LOWFAT_SIZES and LOWFAT_MAGICS data:
        size_t i = 0;
        LOWFAT_SIZES[i++] = SIZE_MAX;
        size_t sizes_len = sizeof(lowfat_sizes) / sizeof(lowfat_sizes[0]);
        for (size_t j = 0; j < sizes_len; j++)
            LOWFAT_SIZES[i++] = lowfat_sizes[j];
        while (((uintptr_t)(LOWFAT_SIZES + i) % LOWFAT_PAGE_SIZE) != 0)
            LOWFAT_SIZES[i++] = SIZE_MAX;
        for (size_t j = 0; j < size_init_len / sizeof(size_t); j++)
            LOWFAT_SIZES[i++] = SIZE_MAX;
        i = 0;
        LOWFAT_MAGICS[i++] = 0;
        for (size_t j = 0; j < sizes_len; j++)
            LOWFAT_MAGICS[i++] = lowfat_magics[j];
        while (((uintptr_t)(LOWFAT_MAGICS + i) % LOWFAT_PAGE_SIZE) != 0)
            LOWFAT_MAGICS[i++] = 0;

        if (!lowfat_protect((void *)LOWFAT_SIZES, len, true, false) ||
            !lowfat_protect((void *)LOWFAT_MAGICS, len, true, false))
            lowfat_error("failed to write protect memory: %s",
                strerror(errno));
    }

#ifndef LOWFAT_DATA_ONLY

    // Init regions for lowfat_malloc()
    for (size_t i = 1; i <= LOWFAT_NUM_REGIONS; i++)
    {
        void *heap_start = (uint8_t *)lowfat_region(i) +
            LOWFAT_HEAP_MEMORY_OFFSET;
        void *ptr = lowfat_map(heap_start, LOWFAT_HEAP_MEMORY_SIZE, false,
            false, -1);
        if (ptr != heap_start)
            goto mmap_error;
    }

    // Initialize malloc()
    if (!lowfat_malloc_init())
        lowfat_error("failed to initialize lowfat malloc(): %s",
            strerror(errno));
    lowfat_malloc_inited = true;

#if !defined(LOWFAT_STANDALONE) && !defined(LOWFAT_WINDOWS)

    // Init regions for the stack
#ifndef LOWFAT_NO_MEMORY_ALIAS
    {
        int fd = lowfat_create_shm(LOWFAT_STACK_MEMORY_SIZE);
        size_t idx;
        for (size_t i = 0; (idx = lowfat_stacks[i]) != 0; i++)
        {
            void *stack_start = (uint8_t *)lowfat_region(idx) +
                LOWFAT_STACK_MEMORY_OFFSET;
            void *ptr = lowfat_map(stack_start, LOWFAT_STACK_MEMORY_SIZE,
                false, false, fd);
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
        void *stack_start = (uint8_t *)lowfat_region(idx) +
            LOWFAT_STACK_MEMORY_OFFSET;
        void *ptr = lowfat_map(stack_start, LOWFAT_STACK_MEMORY_SIZE, false,
            false, -1);
        if (ptr != stack_start)
            goto mmap_error;
    }
#endif /* LOWFAT_NO_MEMORY_ALIAS */

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
    action.sa_flags |= SA_ONSTACK | SA_SIGINFO;
    sigaction(SIGSEGV, &action, NULL);

    // Replace stack with LOWFAT stack.
    lowfat_stack_pivot();

#endif
#endif /* LOWFAT_DATA_ONLY */
}

extern inline size_t lowfat_index(const void *ptr);
extern inline size_t lowfat_size(const void *ptr);
extern inline size_t lowfat_buffer_size(const void *ptr);

static LOWFAT_CONST void *lowfat_region(size_t idx)
{
    return (void *)(idx * LOWFAT_REGION_SIZE);
}

extern LOWFAT_CONST void *lowfat_stack_mirror(void *ptr, ssize_t offset)
{
    return (void *)((uint8_t *)ptr + offset);
}

extern LOWFAT_CONST ssize_t lowfat_stack_offset(size_t idx)
{
    return lowfat_stack_offsets[idx];
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

#if !defined(LOWFAT_DATA_ONLY) && !defined(LOWFAT_STANDALONE) && \
    !defined(LOWFAT_WINDOWS)

/*
 * Perform a "stack pivot"; replacing the stack with the LOWFAT stack.
 * Unfortunately there is no way in Linux to specify the location of the stack
 * before the program starts up, hence the need for some hacks.
 * This code is likely fragile & non-portable.
 */
extern LOWFAT_NOINLINE void *lowfat_stack_pivot_2(void *stack_top)
{
    // Get the stack using the "environment pointer" method.  This assumes
    // that the environment is stored at the base of the stack, which is
    // currently true for Linux.  It is also necessary to copy the argv/env
    // since we patch the stack.
    if (lowfat_envp == NULL)
        lowfat_error("failed to get the environment pointer");
    char **envp = lowfat_envp;
    lowfat_envp = NULL;
    uint8_t *stack_bottom = (void *)envp;
    while (*envp != NULL)
    {
        char *var = *envp;
        uint8_t *end = (uint8_t *)(var + strlen(var) + 1);
        stack_bottom = (stack_bottom < end? end: stack_bottom);
        envp++;
    }
    stack_bottom = (stack_bottom < (uint8_t *)envp? (uint8_t *)envp:
        stack_bottom);
    if (((uintptr_t)stack_bottom % LOWFAT_PAGE_SIZE) != 0)
        stack_bottom = stack_bottom +
            (LOWFAT_PAGE_SIZE - (uintptr_t)stack_bottom % LOWFAT_PAGE_SIZE);

    // Copy the stack contents to a new LowFat-allocated stack:
    size_t size = stack_bottom - (uint8_t *)stack_top;
    uint8_t *stack_base = (uint8_t *)lowfat_stack_alloc();
    if (stack_base == NULL)
        lowfat_error("failed to allocate stack: %s", strerror(errno));
    stack_base += LOWFAT_STACK_SIZE;
    memcpy(stack_base - size, stack_top, size);

    // In some cases the old stack value may be stored on the stack itself,
    // and restored later.  To fix this we search for and replace old
    // stack pointers stored on the the stack itself.  There is a small
    // chance that we may patch an unrelated value.
    void *old_stack_lo = stack_top, *old_stack_hi = stack_bottom;
    void **new_stack_lo = (void **)(stack_base - size),
         **new_stack_hi = (void **)stack_base;
    for (void **pptr = new_stack_lo; pptr < new_stack_hi; pptr++)
    {
        void *ptr = *pptr;
        if (ptr >= old_stack_lo && ptr <= old_stack_hi)
        {
            ssize_t diff = ((uint8_t *)ptr - (uint8_t *)old_stack_lo);
            void *new_ptr = (uint8_t *)new_stack_lo + diff;
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
 * object constructors/initializers may be called before lowfat_init().  We
 * also save the environment pointer so we can later derive the stack base.
 */
void lowfat_preinit(int argc, char **argv, char **envp)
{
	lowfat_envp = envp;
	lowfat_init();
}
__attribute__((section(".preinit_array"), used))
void (*__local_effective_preinit)(int argc, char **argv, char **envp) =
	lowfat_preinit;

#endif

