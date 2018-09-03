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

#ifndef __LOWFAT_H
#define __LOWFAT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus 
extern "C"
{
#endif

#define _LOWFAT_CONST      __attribute__((__const__))
#define _LOWFAT_NORETURN   __attribute__((__noreturn__))
#define _LOWFAT_MALLOC     __attribute__((__malloc__))
#define _LOWFAT_INLINE     __attribute__((__always_inline__))

#define LOWFAT_OOB_ERROR_READ               0
#define LOWFAT_OOB_ERROR_WRITE              1
#define LOWFAT_OOB_ERROR_MEMCPY             2
#define LOWFAT_OOB_ERROR_MEMSET             3
#define LOWFAT_OOB_ERROR_STRDUP             4
#define LOWFAT_OOB_ERROR_ESCAPE_CALL        5
#define LOWFAT_OOB_ERROR_ESCAPE_RETURN      6
#define LOWFAT_OOB_ERROR_ESCAPE_STORE       7
#define LOWFAT_OOB_ERROR_ESCAPE_PTR2INT     8
#define LOWFAT_OOB_ERROR_ESCAPE_INSERT      9
#define LOWFAT_OOB_ERROR_UNKNOWN            0xFF

#include <lowfat_config.h>

/*
 * Tests if the given pointer is low-fat or not.
 */
extern _LOWFAT_CONST bool lowfat_is_ptr(const void *_ptr);

/*
 * Tests if the given pointer is a low-fat heap pointer or not.
 */
extern _LOWFAT_CONST bool lowfat_is_heap_ptr(const void *_ptr);

/*
 * Tests if the given pointer is a low-fat stack pointer or not.
 */
extern _LOWFAT_CONST bool lowfat_is_stack_ptr(const void *_ptr);

/*
 * Tests if the given pointer is a low-fat global pointer or not.
 */
extern _LOWFAT_CONST bool lowfat_is_global_ptr(const void *_ptr);

/*
 * Return the region index of the given pointer.
 */
static inline _LOWFAT_INLINE size_t lowfat_index(const void *_ptr)
{
    return (uintptr_t)_ptr / _LOWFAT_REGION_SIZE;
}

/*
 * Return the (allocation) size of the object pointed to by `_ptr', measured 
 * from the object's base address.  If the size is unknown then this function
 * returns SIZE_MAX.
 */
static inline _LOWFAT_CONST _LOWFAT_INLINE size_t lowfat_size(const void *_ptr)
{
    size_t _idx = lowfat_index(_ptr);
    return _LOWFAT_SIZES[_idx];
}

#ifndef LOWFAT_IS_POW2
/*
 * Return the "object index" of the object pointed to by `_ptr', defined as
 * objidx = _ptr / lowfat_size(_ptr).  Not implemented in POW2-mode.
 */
static inline _LOWFAT_CONST _LOWFAT_INLINE size_t lowfat_objidx(
        const void *_ptr)
{
    size_t _idx = lowfat_index(_ptr);
    unsigned __int128 _tmp = (unsigned __int128)_LOWFAT_MAGICS[_idx] *
        (unsigned __int128)(uintptr_t)_ptr;
    size_t _objidx = (size_t)(_tmp >> 64);
    return _objidx;
}
#endif  /* LOWFAT_IS_POW2 */

/*
 * Return the base-pointer of the object pointed to by `_ptr'.  If the base
 * pointer is unknown then this functon returns NULL.
 */
static inline _LOWFAT_CONST _LOWFAT_INLINE void *lowfat_base(const void *_ptr)
{
    size_t _idx = lowfat_index(_ptr);
#ifndef LOWFAT_IS_POW2
    size_t _objidx = lowfat_objidx(_ptr);
    return (void *)(_objidx * _LOWFAT_SIZES[_idx]);
#else   /* LOWFAT_IS_POW2 */
    return (void *)((uintptr_t)_ptr & _LOWFAT_MAGICS[_idx]);
#endif  /* LOWFAT_IS_POW2 */
}

/*
 * Return the low-fat magic number for `_ptr'.
 */
static inline _LOWFAT_CONST _LOWFAT_INLINE size_t lowfat_magic(const void *_ptr)
{
    size_t _idx = lowfat_index(_ptr);
    return _LOWFAT_MAGICS[_idx];
}

/*
 * Return the (allocation) size of the buffer pointed to by `_ptr', measured
 * from `_ptr' itself.  If the size is unknown then this function returns
 * (SIZE_MAX - (uintptr_t)_ptr).
 */
static inline _LOWFAT_CONST _LOWFAT_INLINE size_t lowfat_buffer_size(
    const void *_ptr)
{
    return lowfat_size(_ptr) -
        ((const uint8_t *)(_ptr) - (const uint8_t *)lowfat_base(_ptr));
}

/*
 * Report an out-of-bounds memory error and abort execution.
 */
extern _LOWFAT_NORETURN void lowfat_oob_error(unsigned _info,
    const void *_ptr, const void *_baseptr);

/*
 * Report an out-of-bounds memory error was a warning only.
 */
extern void lowfat_oob_warning(unsigned _info, const void *_ptr,
    const void *_baseptr);

/*
 * Check if the given pointer is OOB.  If it is then abort with a call to
 * lowfat_oob_error().
 */
extern void lowfat_oob_check(unsigned _info, const void *_ptr, size_t _size,
    const void *_baseptr);

/*
 * Safe replacement malloc().
 */
extern _LOWFAT_MALLOC void *lowfat_malloc(size_t _size);

/*
 * Safe replacement free().
 */
extern void lowfat_free(void *_ptr);

/*
 * Safe replacement realloc().
 */
extern void *lowfat_realloc(void *_ptr, size_t _size);

/*
 * Safe replacement calloc().
 */
extern _LOWFAT_MALLOC void *lowfat_calloc(size_t _nmemb, size_t _size);

/*
 * Safe replacement posix_memalign().
 */
extern int lowfat_posix_memalign(void **memptr, size_t align, size_t size);

/*
 * Safe replacement memalign().
 */
extern _LOWFAT_MALLOC void *lowfat_memalign(size_t _align, size_t _size);

/*
 * Safe replacement aligned_alloc().
 */
extern _LOWFAT_MALLOC void *lowfat_aligned_alloc(size_t _align, size_t _size);

/*
 * Safe replacement valloc().
 */
extern _LOWFAT_MALLOC void *lowfat_valloc(size_t _size);

/*
 * Safe replacment pvalloc().
 */
extern _LOWFAT_MALLOC void *lowfat_pvalloc(size_t _size);

/*
 * Safe replacement strdup().
 */
extern _LOWFAT_MALLOC char *lowfat_strdup(const char *_str);

/*
 * Safe replacement strndup().
 */
extern _LOWFAT_MALLOC char *lowfat_strndup(const char *_str, size_t _n);

/*
 * Safe replacement memset().
 */
extern void *lowfat_memset(void *_dst, int _c, size_t _n);

/*
 * Safe replacement memmove().
 */
extern void *lowfat_memmove(void *_dst, const void *_src, size_t _n);

/*
 * Safe replacement memcpy().
 */
extern void *lowfat_memcpy(void *_dst, const void *_src, size_t _n);

/*
 * Print an error and exit.
 */
extern _LOWFAT_NORETURN void lowfat_error(const char *format, ...);

/*
 * Print a warning.
 */
extern void lowfat_warning(const char *format, ...);

/*
 * Get the number of errors that have been detected so far.
 */
extern size_t lowfat_get_num_errors(void);

#ifdef __cplusplus 
}
#endif

#endif      /* __LOWFAT_H */
