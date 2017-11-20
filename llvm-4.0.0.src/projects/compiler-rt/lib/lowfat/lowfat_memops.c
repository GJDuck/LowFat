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

/*
 * LOWFAT memset
 */
extern void *lowfat_memset(void *dst, int c, size_t n)
{
    size_t size = lowfat_buffer_size(dst);
    if (size < n)
        lowfat_oob_error(LOWFAT_OOB_ERROR_MEMSET, (uint8_t *)dst + size,
            lowfat_base(dst));
    return memset(dst, c, n);
}

/*
 * LOWFAT memmove
 */
extern void *lowfat_memmove(void *dst, const void *src, size_t n)
{
    size_t src_size = lowfat_buffer_size(src);
    if (src_size < n)
        lowfat_oob_error(LOWFAT_OOB_ERROR_MEMCPY, (uint8_t *)src + src_size,
            lowfat_base(src));
    size_t dst_size = lowfat_buffer_size(dst);
    if (dst_size < n)
        lowfat_oob_error(LOWFAT_OOB_ERROR_MEMCPY, (uint8_t *)dst + dst_size,
            lowfat_base(dst));
    return memmove(dst, src, n);
}

/*
 * LOWFAT memcpy
 */
extern void *lowfat_memcpy(void *dst, const void *src, size_t n)
{
    return lowfat_memmove(dst, src, n);
}

