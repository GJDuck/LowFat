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

/*
 * This is a fixed configuration for the Windows build.
 */

#ifndef __LOWFAT_CONFIG_H
#define __LOWFAT_CONFIG_H

#define _LOWFAT_SIZES ((size_t *)0x50000000)
#define _LOWFAT_MAGICS ((uint64_t *)0x51000000)
#define _LOWFAT_REGION_SIZE 34359738368ull

#endif	/* __LOWFAT_CONFIG_H */
