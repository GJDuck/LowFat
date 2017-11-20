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
 * These functions are implemented in a different module to prevent LLVM
 * optimizations interfering with the test suite.
 */

#include <stdint.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

extern void *ptr;

template <typename T>
T **getptr(void)
{
    return (T **)&ptr;
}

template uint8_t **getptr<uint8_t>(void);
template uint16_t **getptr<uint16_t>(void);
template uint32_t **getptr<uint32_t>(void);
template uint64_t **getptr<uint64_t>(void);

template <typename T>
T get(T *ptr, int offset)
{
    return ptr[offset];
}

template uint8_t get<uint8_t>(uint8_t *ptr, int offset);
template uint16_t get<uint16_t>(uint16_t *ptr, int offset);
template uint32_t get<uint32_t>(uint32_t *ptr, int offset);
template uint64_t get<uint64_t>(uint64_t *ptr, int offset);

template <typename T>
void set(T *ptr, int offset, T val)
{
    ptr[offset] = val;
}

template void set<uint8_t>(uint8_t *ptr, int offset, uint8_t val);
template void set<uint16_t>(uint16_t *ptr, int offset, uint16_t val);
template void set<uint32_t>(uint32_t *ptr, int offset, uint32_t val);
template void set<uint64_t>(uint64_t *ptr, int offset, uint64_t val);

template <typename T>
void escape(T *ptr)
{
    // NOP
}

template void escape<uint8_t>(uint8_t *ptr);
template void escape<uint16_t>(uint16_t *ptr);
template void escape<uint32_t>(uint32_t *ptr);
template void escape<uint64_t>(uint64_t *ptr);

void escape(uintptr_t i)
{
    // NOP
}

template <typename T>
T *doreturn(T *ptr, int offset)
{
    return ptr + offset;
}

template uint8_t *doreturn<uint8_t>(uint8_t *ptr, int offset);
template uint16_t *doreturn<uint16_t>(uint16_t *ptr, int offset);
template uint32_t *doreturn<uint32_t>(uint32_t *ptr, int offset);
template uint64_t *doreturn<uint64_t>(uint64_t *ptr, int offset);

size_t id(size_t size)
{
    return size;
}

