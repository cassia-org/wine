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

#include <string.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winreg.h"
#include "winnls.h"

#include "wine/unixlib.h"
#include "wine/debug.h"
#include "wine/exception.h"

WINE_DEFAULT_DEBUG_CHANNEL(wow);

static const UINT_PTR page_mask = 0xfff;

#define ROUND_ADDR(addr,mask) ((void *)((UINT_PTR)(addr) & ~(UINT_PTR)(mask)))
#define ROUND_SIZE(addr,size) (((SIZE_T)(size) + ((UINT_PTR)(addr) & page_mask) + page_mask) & ~page_mask)

/* Used to indicate that an i386 context contains a 'host_restore_stack_layout' struct on its stack, which should be used in BTCpuSimulate to return from an exception */
#define CONTEXT_I386_HAS_HOST_CONTEXT (1 << 30)

static void (*pho_init)(void);
static void (*pho_run)( DWORD64 teb, I386_CONTEXT *ctx );
static void (*pho_invalidate_code_range)( DWORD64 start, DWORD64 length );
static void (*pho_reconstruct_x86_context)( I386_CONTEXT *wow_context, CONTEXT *context );
static BOOLEAN (*pho_unaligned_access_handler)( CONTEXT *context );
static BOOLEAN (*pho_address_in_jit)( DWORD64 addr );

struct host_restore_stack_layout {
    DWORD saved_eip;
    DWORD pad;
    CONTEXT arm_context;
};

static void *get_wow_teb( TEB *teb )
{
    return teb->WowTebOffset ? (void *)((char *)teb + teb->WowTebOffset) : NULL;
}

static void emu_run( I386_CONTEXT *context )
{
    pho_run( (DWORD64)get_wow_teb( NtCurrentTeb() ), context );
}

static NTSTATUS initialize(void)
{
    HMODULE module;
    UNICODE_STRING str;
    NTSTATUS status;

    RtlInitUnicodeString( &str, L"libhofex" );
    status = LdrLoadDll( NULL, 0, &str, &module );
    if (!NT_SUCCESS( status ))
        return status;

#define LOAD_FUNCPTR(f) if((p##f = (void*)RtlFindExportedRoutineByName( module, #f )) == NULL) { ERR( #f " %p\n", p##f ); return STATUS_ENTRYPOINT_NOT_FOUND; }
    LOAD_FUNCPTR(ho_init);
    LOAD_FUNCPTR(ho_run);
    LOAD_FUNCPTR(ho_invalidate_code_range);
    LOAD_FUNCPTR(ho_reconstruct_x86_context);
    LOAD_FUNCPTR(ho_unaligned_access_handler);
    LOAD_FUNCPTR(ho_address_in_jit);
#undef LOAD_FUNCPTR

    pho_init();
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI Wow64SystemServiceEx( UINT num, UINT *args );

static const UINT16 bopcode = 0x2ecd;
static const UINT16 unxcode = 0x2ecd;

static NTSTATUS (WINAPI *p__wine_unix_call)( unixlib_handle_t, unsigned int, void * );

static void handle_unix_call( I386_CONTEXT *c )
{
    unixlib_handle_t *handle;
    UNICODE_STRING str;
    HMODULE module;
    UINT32 *p, p0;
    NTSTATUS ret;

    p = ULongToPtr( c->Esp );
    handle = (void *)&p[1];

    if (!p__wine_unix_call)
    {
        RtlInitUnicodeString( &str, L"ntdll.dll" );
        LdrGetDllHandle( NULL, 0, &str, &module );
        p__wine_unix_call = RtlFindExportedRoutineByName( module, "__wine_unix_call" );
    }

    p0 = p[0];
    ret = p__wine_unix_call( *handle, p[3], ULongToPtr( p[4] ) );
    c->Eip = p0;
    c->Esp += 4+8+4+4; /* ret + args */
    c->Eax = ret;
}

static void handle_syscall( I386_CONTEXT *c )
{
    I386_CONTEXT *wow_context;
    NTSTATUS ret;
    RtlWow64GetCurrentCpuArea( NULL, (void **)&wow_context, NULL );
    ret = Wow64SystemServiceEx( wow_context->Eax, ULongToPtr( wow_context->Esp + 8 ) );
    if (ULongToPtr( wow_context->Eip ) == &bopcode)
    {
        wow_context->Eip = *(DWORD *)ULongToPtr( wow_context->Esp );
        wow_context->Esp += 4;
        wow_context->Eax = ret;
    }
}


/**********************************************************************
 *           BTCpuProcessInit  (xtajit.@)
 */
void WINAPI BTCpuSimulate(void)
{
    I386_CONTEXT *wow_context;
    NTSTATUS ret;

    RtlWow64GetCurrentCpuArea( NULL, (void **)&wow_context, NULL );

    if (wow_context->ContextFlags & CONTEXT_I386_HAS_HOST_CONTEXT)
    {
        struct host_restore_stack_layout *stack = (struct host_restore_stack_layout *)(wow_context->Esp);

        /* Restore context to initial state */
        wow_context->ContextFlags &= ~CONTEXT_I386_HAS_HOST_CONTEXT;
        wow_context->Esp += sizeof(struct host_restore_stack_layout);

        /* If an exception handler has changed the EIP, hope that the reconstructed context will be
         * enough, otherwise continue from the host context */
        if (stack->saved_eip == wow_context->Eip)
        {
            FIXME( "Continuing with host context: %#lx\n", wow_context->Eip );
            NtContinue( &stack->arm_context, FALSE );
        }
        else
        {
            FIXME( "Continuing with reconstructed context: %#lx\n", wow_context->Eip );
        }
    }

    emu_run( wow_context );

    if (ULongToPtr( wow_context->Eip ) == &unxcode)
    {
        /* unix call */
        handle_unix_call( wow_context );
    }
    else if (ULongToPtr( wow_context->Eip ) == &bopcode)
    {
        /* sys call */
        handle_syscall( wow_context );
    }
    else
    {
        DWORD arg[] = {0xffffffff, 1};

        ERR( "Client crashed\n" );
        ERR( "EIP %p\n", ULongToPtr( wow_context->Eip ) );
        ERR( "bop %p\n", &bopcode );

        /* NtTerminateProcess */
        Wow64SystemServiceEx( 212, (UINT*)&arg );
        return;
    }
}


/**********************************************************************
 *           BTCpuProcessInit  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuProcessInit(void)
{
    if ((ULONG_PTR)BTCpuProcessInit >> 32)
    {
        ERR( "xtajit loaded above 4G, disabling\n" );
        return STATUS_INVALID_ADDRESS;
    }
    return STATUS_SUCCESS;
}

/**********************************************************************
 *           BTCpuThreadInit  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuThreadInit(void)
{
    return STATUS_SUCCESS;
}

/**********************************************************************
 *           BTCpuGetBopCode  (xtajit.@)
 */
void * WINAPI BTCpuGetBopCode(void)
{
    return (UINT32*)&bopcode;
}

void * WINAPI __wine_get_unix_opcode(void)
{
    return (UINT32*)&unxcode;
}

/**********************************************************************
 *           BTCpuGetContext  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuGetContext( HANDLE thread, HANDLE process, void *unknown, I386_CONTEXT *ctx )
{
    return NtQueryInformationThread( thread, ThreadWow64Context, ctx, sizeof(*ctx), NULL );
}


/**********************************************************************
 *           BTCpuSetContext  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuSetContext( HANDLE thread, HANDLE process, void *unknown, I386_CONTEXT *ctx )
{
    return NtSetInformationThread( thread, ThreadWow64Context, ctx, sizeof(*ctx) );
}

/**********************************************************************
 *           BTCpuResetToConsistentState  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuResetToConsistentState( EXCEPTION_POINTERS *ptrs )
{
    struct host_restore_stack_layout *stack;
    CONTEXT *context = ptrs->ContextRecord;
    EXCEPTION_RECORD *exception = ptrs->ExceptionRecord;
    I386_CONTEXT wow_context;

    if (exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && pho_unaligned_access_handler( context ))
        NtContinue( context, FALSE );

    if (!pho_address_in_jit( context->Pc )) return STATUS_SUCCESS;

    TRACE( "Exception under guest %#llx\n", context->Pc );

    FIXME( "Reconstructing context\n" );
    pho_reconstruct_x86_context( &wow_context, context );

    /* Store host state to stack to allow for correctly resuming from synchronous exceptions */
    wow_context.ContextFlags |= CONTEXT_I386_HAS_HOST_CONTEXT;
    wow_context.Esp -= sizeof(struct host_restore_stack_layout);

    stack = (struct host_restore_stack_layout *)(wow_context.Esp);
    stack->saved_eip = wow_context.Eip;
    stack->arm_context = *context;

    BTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &wow_context );

    /* TODO: fixup context */
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           BTCpuTurboThunkControl  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuTurboThunkControl( ULONG enable )
{
    FIXME( "NYI\n" );
    if (enable) return STATUS_NOT_SUPPORTED;
    /* we don't have turbo thunks yet */
    return STATUS_SUCCESS;
}

/**********************************************************************
 *           invalidate_mapped_section
 *
 * Invalidates all code in the entire memory section containing 'addr'
 */
static NTSTATUS invalidate_mapped_section( PVOID addr )
{

    MEMORY_BASIC_INFORMATION mem_info;
    NTSTATUS ret = NtQueryVirtualMemory( NtCurrentProcess(), addr, MemoryBasicInformation, &mem_info,
                                         sizeof(mem_info), NULL );

    if (!NT_SUCCESS(ret))
        return ret;

    pho_invalidate_code_range( (DWORD64)mem_info.AllocationBase,
                               (DWORD64)mem_info.BaseAddress + mem_info.RegionSize - (DWORD64)mem_info.AllocationBase );
    return STATUS_SUCCESS;
}

/**********************************************************************
 *           BTCpuNotifyUnmapViewOfSection  (xtajit.@)
 */
void WINAPI BTCpuNotifyUnmapViewOfSection( PVOID addr, ULONG flags )
{
    NTSTATUS ret = invalidate_mapped_section( addr );
    if (!NT_SUCCESS(ret))
        WARN( "Failed to invalidate code memory: %#lx\n", ret );
}

/**********************************************************************
 *           BTCpuNotifyMemoryFree  (xtajit.@)
 */
void WINAPI BTCpuNotifyMemoryFree( PVOID addr, SIZE_T size, ULONG free_type )
{
    if (!size)
    {
        NTSTATUS ret = invalidate_mapped_section( addr );
        if (!NT_SUCCESS(ret))
            WARN( "Failed to invalidate code memory: %#lx\n", ret );
    }
    else if (free_type & MEM_DECOMMIT)
    {
        /* Invalidate all pages touched by the region, even if they are just straddled */
        pho_invalidate_code_range( (DWORD64)ROUND_ADDR( addr, page_mask ), (DWORD64)ROUND_SIZE( addr, size ) );
    }
}

/**********************************************************************
 *           BTCpuNotifyMemoryProtect  (xtajit.@)
 */
void WINAPI BTCpuNotifyMemoryProtect( PVOID addr, SIZE_T size, DWORD new_protect )
{
    if (!(new_protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        return;

    /* Invalidate all pages touched by the region, even if they are just straddled */
    pho_invalidate_code_range( (DWORD64)ROUND_ADDR( addr, page_mask ), (DWORD64)ROUND_SIZE( addr, size ) );
}

/**********************************************************************
 *           BTCpuFlushInstructionCache2  (xtajit.@)
 */
void WINAPI BTCpuFlushInstructionCache2( LPCVOID addr, SIZE_T size)
{
    /* Invalidate all pages touched by the region, even if they are just straddled */
    pho_invalidate_code_range( (DWORD64)addr, (DWORD64)size );
}

BOOL WINAPI DllMain (HINSTANCE inst, DWORD reason, void *reserved )
{
    TRACE("%p,%lx,%p\n", inst, reason, reserved);

    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            LdrDisableThreadCalloutsForDll( inst );
            initialize();
            break;
        case DLL_PROCESS_DETACH:
            if (reserved) break;
            ERR( "Implement detach\n" );
            break;
    }

    return TRUE;
}
