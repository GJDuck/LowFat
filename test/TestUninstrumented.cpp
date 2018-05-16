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

#include <cstdlib>

#include <lowfat.h>

#define TEST_FUNC(func, type, statement)                                    \
    bool func(type *ptr)                                                    \
    {                                                                       \
        size_t size = lowfat_size(ptr);                                     \
        statement;                                                          \
        if (size != SIZE_MAX) {                                             \
            void *ptr1 = lowfat_malloc(size-1);                             \
            bool ok = (ptr == ptr1);                                        \
            lowfat_free(ptr1);                                              \
            return ok;                                                      \
        } else                                                              \
            return false;                                                   \
    }

TEST_FUNC(myFree, void, free(ptr));
TEST_FUNC(myDelete, int, delete ptr);
TEST_FUNC(myRealloc, void, void *tmp = realloc(ptr, 1000); free(tmp));

