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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowfat_config.c"

/*
 * Slow definitions that do not depend on the LowFat runtime system:
 */

static size_t lowfat_index(const void *ptr)
{
    return (uintptr_t)ptr / _LOWFAT_REGION_SIZE;
}

static void *lowfat_region(const void *ptr)
{
    return (void *)(lowfat_index(ptr) * LOWFAT_REGION_SIZE);
}

static bool lowfat_is_ptr(const void *ptr)
{
    size_t idx = lowfat_index(ptr);
    return (idx != 0 && idx <= LOWFAT_NUM_REGIONS+1);
}

static bool lowfat_is_heap_ptr(const void *ptr)
{
    if (!lowfat_is_ptr(ptr))
        return false;
    void *heap_lo = lowfat_region(ptr) + LOWFAT_HEAP_MEMORY_OFFSET;
    void *heap_hi = heap_lo + LOWFAT_HEAP_MEMORY_SIZE;
    return (ptr >= heap_lo && ptr < heap_hi);
}

static bool lowfat_is_stack_ptr(const void *ptr)
{
    if (!lowfat_is_ptr(ptr))
        return false;
    void *stack_lo = lowfat_region(ptr) + LOWFAT_STACK_MEMORY_OFFSET;
    void *stack_hi = stack_lo + LOWFAT_STACK_MEMORY_SIZE;
    return (ptr >= stack_lo && ptr < stack_hi);
}

static bool lowfat_is_global_ptr(const void *ptr)
{
    if (!lowfat_is_ptr(ptr))
        return false;
    void *global_lo = lowfat_region(ptr) + LOWFAT_GLOBAL_MEMORY_OFFSET;
    void *global_hi = global_lo + LOWFAT_GLOBAL_MEMORY_SIZE;
    return (ptr >= global_lo && ptr < global_hi);
}

static size_t lowfat_size(const void *ptr)
{
    if (!lowfat_is_ptr(ptr))
        return SIZE_MAX;
    else
        return lowfat_sizes[lowfat_index(ptr)-1];
}

static size_t lowfat_magic(const void *ptr)
{
    size_t idx = lowfat_index(ptr);
    if (!lowfat_is_ptr(ptr))
        return 0;
    else
        return lowfat_magics[lowfat_index(ptr)-1];
}

static void *lowfat_base(const void *ptr)
{
    uintptr_t iptr = (uintptr_t)ptr;
    size_t size = lowfat_size(ptr);
    iptr -= iptr % size;
    return (void *)iptr;
}

/*
 * Main.
 */
int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s ptr\n", argv[0]);
        return EXIT_FAILURE;
    }
    void *ptr = NULL;
    if (argv[1][0] == '0' && argv[1][1] == 'x')
        ptr = (void *)strtoull(argv[1], NULL, 16);
    else
        ptr = (void *)strtoull(argv[1], NULL, 10);
    const char *type =
        (lowfat_is_heap_ptr(ptr)? "heap":
        (lowfat_is_stack_ptr(ptr)? "stack":
        (lowfat_is_global_ptr(ptr)? "global":
        (lowfat_is_ptr(ptr)? "unused": "nonfat"))));
    printf("ptr    = %p\n", ptr);
    printf("type   = %s\n", type);
    printf("region = #%zu (%p)\n", lowfat_index(ptr), lowfat_region(ptr));
    printf("base   = %p\n", lowfat_base(ptr));
    printf("size   = %zu (0x%zx)\n", lowfat_size(ptr), lowfat_size(ptr));
    printf("magic  = %zu (0x%zx)\n", lowfat_magic(ptr), lowfat_magic(ptr));
    printf("offset = %zu\n", ptr - lowfat_base(ptr));
    return 0;
}

