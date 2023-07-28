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

/* Stores a pointer to the host context as it was just before JIT entry, used to allow guest exceptions to unwind to the wow exception handler */
#define FEXCORE_TLS_ENTRY_CTX 12

/* Stores a control bitset to allow for modifying and observing the state of a WOW thread */
#define FEXCORE_TLS_CONTROL_WORD 13

/* The context stored in the WOW CPU area is guaranteed to be up-to-date if this bit is unset */
#define CONTROL_IN_JIT 1LL

/* JIT entry polls this bit until it is unset, at which point CONTROL_IN_JIT will be set */
#define CONTROL_PAUSED 2LL


static void (*pho_init)(void);
static void (*pho_run)( DWORD64 teb, I386_CONTEXT *ctx );
static void (*pho_invalidate_code_range)( DWORD64 start, DWORD64 length );
static void (*pho_reconstruct_x86_context)( I386_CONTEXT *wow_context, CONTEXT *context );
static BOOLEAN (*pho_unaligned_access_handler)( CONTEXT *context );
static BOOLEAN (*pho_address_in_jit)( DWORD64 addr );
static void (*pho_request_thread_return)( TEB *thread_teb );
static void (*pho_thread_init)(void);
static void (*pho_thread_terminate)( TEB *thread_teb );

static void *get_wow_teb( TEB *teb )
{
    return teb->WowTebOffset ? (void *)((char *)teb + teb->WowTebOffset) : NULL;
}

static void emu_run( I386_CONTEXT *context )
{
    CONTEXT entry_context;
    LONG64 *control_word = (LONG64 *)&NtCurrentTeb()->TlsSlots[FEXCORE_TLS_CONTROL_WORD];
    LONG64 expected_val;

    RtlCaptureContext( &entry_context );
    NtCurrentTeb()->TlsSlots[FEXCORE_TLS_ENTRY_CTX] = &entry_context;

    /* Spin until CONTROL_PAUSED is unset, setting CONTROL_IN_JIT when that occurs */
    do {
        expected_val = *control_word & ~CONTROL_PAUSED;
    } while (InterlockedCompareExchange64( control_word, expected_val | CONTROL_IN_JIT, expected_val ) != expected_val);

    pho_run( (DWORD64)get_wow_teb( NtCurrentTeb() ), context );

    InterlockedAnd64( control_word, ~CONTROL_IN_JIT );
}

static NTSTATUS initialize(void)
{
    HMODULE module;
    UNICODE_STRING str;
    NTSTATUS status;

    RtlInitUnicodeString( &str, L"libhofex" );
    status = LdrLoadDll( L"C:\\windows\\system32\\", 0, &str, &module );
    if (!NT_SUCCESS( status ))
        return status;

#define LOAD_FUNCPTR(f) if((p##f = (void*)RtlFindExportedRoutineByName( module, #f )) == NULL) { ERR( #f " %p\n", p##f ); return STATUS_ENTRYPOINT_NOT_FOUND; }
    LOAD_FUNCPTR(ho_init);
    LOAD_FUNCPTR(ho_run);
    LOAD_FUNCPTR(ho_invalidate_code_range);
    LOAD_FUNCPTR(ho_reconstruct_x86_context);
    LOAD_FUNCPTR(ho_unaligned_access_handler);
    LOAD_FUNCPTR(ho_address_in_jit);
    LOAD_FUNCPTR(ho_request_thread_return);
    LOAD_FUNCPTR(ho_thread_init);
    LOAD_FUNCPTR(ho_thread_terminate);
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
}


/**********************************************************************
 *            BTCpuSuspendLocalThread (xtajit.@)
 */
NTSTATUS WINAPI BTCpuSuspendLocalThread( HANDLE thread, ULONG *count )
{
    THREAD_BASIC_INFORMATION tbi;
    TEB *thread_teb;
    LONG64 *control_word;
    CONTEXT tmp_context;
    NTSTATUS ret = NtQueryInformationThread( thread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
    if (ret) return ret;

    thread_teb = tbi.TebBaseAddress;
    control_word = (LONG64 *)&thread_teb->TlsSlots[FEXCORE_TLS_CONTROL_WORD];

    TRACE( "Suspending thread: %p\n", thread_teb->ClientId.UniqueThread );

    InterlockedOr64( control_word, CONTROL_PAUSED );

    /* If CONTROL_IN_JIT is unset at this point, then it can never be set (and thus the JIT cannot
     * be reentered) as CONTROL_PAUSED has been set, as such, while this may redundantly request
     * returns in rare cases it will never miss them */
    if (*control_word & CONTROL_IN_JIT)
    {
        TRACE( "Thread %p is in JIT, polling for return\n", thread_teb->ClientId.UniqueThread );
        pho_request_thread_return( thread_teb );
    }

    /* Spin until the JIT returns */
    while (InterlockedOr64( control_word, 0 ) & CONTROL_IN_JIT);

    /* The JIT has now returned and the context stored in the thread's CPU area is up-to-date */
    ret = NtSuspendThread( thread, count );
    if (ret)
        goto end;

    tmp_context.ContextFlags = CONTEXT_INTEGER;

    /* NtSuspendThread may return before the thread is actually suspended, so a sync operation
     * like NtGetContextThread needs to be called to ensure it is before we unset CONTROL_PAUSED */
    (void)NtGetContextThread( thread, &tmp_context );

end:
    TRACE( "Thread suspended: %p\n", thread_teb->ClientId.UniqueThread );

    if ( *control_word & CONTROL_IN_JIT ) ERR( "Suspend failed!\n" );

    /* Now the thread is suspended on the host, unset CONTROL_PAUSED so that NtResumeThread will
     * continue execution in the JIT */
    InterlockedAnd64( control_word, ~CONTROL_PAUSED );

    return ret;
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
    pho_thread_init();
    return STATUS_SUCCESS;
}

/**********************************************************************
 *           BTCpuThreadInit  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuThreadTerm( HANDLE thread )
{
    THREAD_BASIC_INFORMATION tbi;
    NTSTATUS ret = NtQueryInformationThread( thread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
    if (ret) return ret;

    pho_thread_terminate( tbi.TebBaseAddress );

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
    CONTEXT *entry_context = NtCurrentTeb()->TlsSlots[FEXCORE_TLS_ENTRY_CTX];
    LONG64 *control_word = (LONG64 *)&NtCurrentTeb()->TlsSlots[FEXCORE_TLS_CONTROL_WORD];

    if (exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && pho_unaligned_access_handler( context ))
        NtContinue( context, FALSE );

    if (!pho_address_in_jit( context->Pc )) return STATUS_SUCCESS;

    FIXME( "Reconstructing context\n" );
    pho_reconstruct_x86_context( &wow_context, context );
    TRACE( "pc: %#llx eip: %#x\n", context->Pc, wow_context.Eip );

    BTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &wow_context );

    InterlockedAnd64( control_word, ~CONTROL_IN_JIT );

    /* Replace the host context with one captured before JIT entry so host code can unwind */
    memcpy( context, entry_context, sizeof(*context) );

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
