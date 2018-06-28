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

#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#ifndef F_SETLEASE
#define F_SETLEASE              1024
#endif

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

static void lowfat_random_page(void *buf)
{
    static bool inited = false;
    static int fd = -1;
    const char *path = "/dev/urandom";
    if (!inited)
    {
        inited = true;
	    fd = open(path, O_RDONLY | O_CLOEXEC);
	    if (fd < 0)
	        lowfat_error("failed to open \"%s\": %s", path, strerror(errno));
    }

	ssize_t r = read(fd, buf, LOWFAT_PAGE_SIZE);
	if (r < 0)
	    lowfat_error("failed to read \"%s\": %s", path, strerror(errno));
	if (r != LOWFAT_PAGE_SIZE)
	    lowfat_error("failed to read %zu bytes from \"%s\"", LOWFAT_PAGE_SIZE,
			path);
}

#include <execinfo.h>
static LOWFAT_NOINLINE void lowfat_backtrace(void)
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
 * Map memory.
 */
static void *lowfat_map(void *ptr, size_t size, bool r, bool w, int fd)
{
	int prot = PROT_NONE;
    if (r)
        prot |= PROT_READ;
    if (w)
        prot |= PROT_WRITE;
    int flags = MAP_NORESERVE;
    if (ptr != NULL)
        flags |= MAP_FIXED;
    if (fd != -1)
        flags |= MAP_SHARED;
    else
        flags |= MAP_ANONYMOUS | MAP_PRIVATE;
    void *ptr1 = mmap(ptr, size, prot, flags, fd, 0);
    if (ptr1 == MAP_FAILED)
        return NULL;
    return ptr1;
}

/*
 * Protect memory.
 */
static bool lowfat_protect(void *ptr, size_t size, bool r, bool w)
{
    int prot = PROT_NONE;
    if (r)
        prot |= PROT_READ;
    if (w)
        prot |= PROT_WRITE;
    if (mprotect(ptr, size, prot) < 0)
        return false;
    return true;
}

/*
 * Free memory.
 */
static void lowfat_dont_need(void *ptr, size_t size)
{
    madvise(ptr, size, MADV_DONTNEED);
}

