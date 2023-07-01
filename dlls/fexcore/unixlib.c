/*
 * Copyright 2022-2023 André Zwing
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "unixlib.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wow);

#define ExitProcess(x) exit(x)

static void (*pho_A)(void);
static void (*pho_B)(uint64_t teb, I386_CONTEXT* ctx);
static void (*pho_invalidate_code_range)(uint64_t start, uint64_t length);

static void *emuapi_handle;

static NTSTATUS attach( void *args )
{
    static char default_lib[] = "/opt/libhofex.so";
    char *holib;

    holib = getenv("HOLIB");
    if (!holib)
        holib = default_lib;

    if (!(emuapi_handle = dlopen( holib, RTLD_NOW )))
    {
        FIXME("%s\n", dlerror());
        return STATUS_DLL_NOT_FOUND;
    }

#define LOAD_FUNCPTR(f) if((p##f = dlsym(emuapi_handle, #f)) == NULL) {ERR(#f " %p\n", p##f);return STATUS_ENTRYPOINT_NOT_FOUND;}
#define LOAD_FUNCPTR_OPT(f) if((p##f = dlsym(emuapi_handle, #f)) == NULL) {ERR(#f " %p\n", p##f);}
    LOAD_FUNCPTR(ho_A);
    LOAD_FUNCPTR(ho_B);
    LOAD_FUNCPTR(ho_invalidate_code_range);
#undef LOAD_FUNCPTR_OPT
#undef LOAD_FUNCPTR

    pho_A();

    return STATUS_SUCCESS;
}

static NTSTATUS detach( void *args )
{
    dlclose( emuapi_handle );
    return STATUS_SUCCESS;
}

static void init_thread_cpu(void)
{
}

static inline void *get_wow_teb( TEB *teb )
{
    return teb->WowTebOffset ? (void *)((char *)teb + teb->WowTebOffset) : NULL;
}

static NTSTATUS emu_run( void *args )
{
    const struct emu_run_params *params = args;
    TEB *teb = NtCurrentTeb();
    DWORD tid = HandleToULong(teb->ClientId.UniqueThread);
    void *wowteb = get_wow_teb(teb);

    if (!params->c->Eip)
    {
        ERR("Attempting to execute NULL.\n");
        ExitProcess(1);
    }

    pho_B(wowteb, params->c);
    return 0;
}

static void invalidate_code_range ( void *args )
{
    const struct invalidate_code_range_params *params = args;
    pho_invalidate_code_range(params->base, params->length);
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    attach,
    detach,
    emu_run,
    invalidate_code_range,
};
