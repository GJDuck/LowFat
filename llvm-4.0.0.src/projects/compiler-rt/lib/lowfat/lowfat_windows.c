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

#include <windows.h>

extern const char *lowfat_color_escape_code(FILE *stream, bool red)
{
	// colors not supported [Windows]
	return "";
}

static void lowfat_random_page(void *buf)
{
    static bool inited = false;
    static BOOLEAN (APIENTRY *func)(void *, ULONG);
    if (!inited)
    {
        inited = true;
        const char *libname = "advapi32.dll";
        HMODULE lib = LoadLibrary(libname);
        if (lib == NULL)
            lowfat_error("failed to load library \"%s\"", libname);
        const char *funcname = "SystemFunction036";
        func = (BOOLEAN (APIENTRY *)(void *, ULONG))
            GetProcAddress(lib, funcname);
        if (func == NULL)
            lowfat_error("failed to load function \"%s\"", funcname);
    }

    if (!func(buf, LOWFAT_PAGE_SIZE))
        lowfat_error("failed to get %zu random bytes", LOWFAT_PAGE_SIZE);
}

static void lowfat_backtrace(void)
{
    // backtrace not supported [Windows]
}

static void *lowfat_map(void *ptr, size_t size, bool r, bool w, int fd)
{
	DWORD prot = PAGE_NOACCESS;
    if (r && !w)
        prot = PAGE_READONLY;
    else if (r && w)
        prot = PAGE_READWRITE;
    DWORD flags = MEM_RESERVE;
    if (r || w)
        flags |= MEM_COMMIT;
	void *result = VirtualAlloc(ptr, size, flags, prot);
    return result;
}

static bool lowfat_protect(void *ptr, size_t size, bool r, bool w)
{
    DWORD prot = PAGE_NOACCESS;
    if (r && !w)
        prot = PAGE_READONLY;
    else if (r && w)
        prot = PAGE_READWRITE;
    if (r || w)
    {
        if (VirtualAlloc(ptr, size, MEM_COMMIT, prot) == NULL)
            return false;
    }
    else
    {
        if (!VirtualProtect(ptr, size, PAGE_NOACCESS, NULL))
            return false;
    }
    return true;
}

static void lowfat_dont_need(void *ptr, size_t size)
{
    // NOP [Windows]
}

void lowfat_init(void);
extern BOOL APIENTRY lowfat_dll_entry(HANDLE module, DWORD reason,
    LPVOID reserved)
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            lowfat_init();
            break;
    }
    return TRUE;
}

