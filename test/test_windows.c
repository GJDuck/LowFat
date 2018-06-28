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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lowfat.h"

static __attribute__((__noinline__)) void print_info(char *ptr)
{
    printf("ptr         = 0x%p\n", ptr);
    printf("size(ptr)   = %lu\n", (unsigned long)lowfat_size(ptr));
    printf("base(ptr)   = 0x%p\n", lowfat_base(ptr));
    printf("offset(ptr) = %lu\n", (unsigned long)
        (ptr - (char *)lowfat_base(ptr)));
    printf("object      = \"");
    char *base = (char *)lowfat_base(ptr);
    size_t size = lowfat_size(ptr);
    for (size_t i = 0; i < size; i++)
    {
        if (isprint(base[i]))
            putchar(base[i]);
        else
            putchar('.');
    }
    printf("\"\n");
}

int __cdecl main(int argc, char **argv)
{
    if (argc != 2 && argc != 3)
    {
        fprintf(stderr, "usage: %s length [offset]\n", argv[0]);
        exit(1);
    }
    size_t size = (size_t)atoi(argv[1]);
    size_t offset = 0;
    if (argc == 3)
        offset = (size_t)atoi(argv[2]);
    if (offset >= size)
    {
        fprintf(stderr, "error: offset must be less than the size\n");
        exit(1);
    }
    char *ptr = lowfat_malloc(size);
    memset(ptr, 'A', size);
    print_info(ptr + offset);
    lowfat_free(ptr);
    return 0;
}

