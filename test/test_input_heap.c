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

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s length\n", argv[0]);
        exit(1);
    }
    size_t size = (size_t)atoi(argv[1]);
    char *buf = (char *)malloc(size);
    printf("malloc(%zu) = %p\n", size, buf);
    printf("Enter a string: ");
    fflush(stdout);
    int i;
    for (i = 0; (buf[i] = getchar()) != '\n'; i++)
        ;
    buf[i] = '\0';
    printf("String = \"%s\"\n", buf);
    return 0;
}

