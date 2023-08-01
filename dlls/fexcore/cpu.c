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

/* When this is unset, a thread can be safely interrupted and have its context recovered */
#define CONTROL_IN_JIT 1

/* JIT entry polls this bit until it is unset, at which point CONTROL_IN_JIT will be set */
#define CONTROL_PAUSED 2

/* When this is set, the CPU context stored in the FEX TLS has not yet been flushed to the CPU area */
#define CONTROL_FEX_CONTEXT_DIRTY 4

/* When this is set, the CPU context stored in the CPU area has not yet been flushed to the FEX TLS */
#define CONTROL_CPU_AREA_DIRTY 8

static void (*pho_init)( void *callback );
static void (*pho_run)(void);
static void (*pho_invalidate_code_range)( DWORD64 start, DWORD64 length );
static void (*pho_reconstruct_wow_context)( I386_CONTEXT *wow_context, CONTEXT *context );
static BOOLEAN (*pho_unaligned_access_handler)( CONTEXT *context );
static BOOLEAN (*pho_address_in_jit)( DWORD64 addr );
static void (*pho_request_thread_return)( TEB *thread_teb );
static void (*pho_thread_init)(void);
static void (*pho_thread_terminate)( TEB *thread_teb );
static void (*pho_thread_set_context)( TEB *thread_teb, DWORD64 wow_teb, I386_CONTEXT *wow_context );
static void (*pho_thread_get_context)( TEB *thread_teb, I386_CONTEXT *wow_context );
static DWORD64 *(*pho_thread_get_returning_stack_ptr)(void);
static void (*pho_run_cpuid_function)( UINT32 function, UINT32 leaf, UINT *regs );

static RTL_CRITICAL_SECTION thread_suspend_cs;
static SYSTEM_CPU_INFORMATION cpu_info;

static const UINT16 bopcode = 0x2ecd;
static const UINT16 unxcode = 0x2ecd;

static void *get_wow_teb( TEB *teb )
{
    return teb->WowTebOffset ? (void *)((char *)teb + teb->WowTebOffset) : NULL;
}

NTSTATUS WINAPI Wow64SystemServiceEx( UINT num, UINT *args );

static NTSTATUS (WINAPI *p__wine_unix_call)( unixlib_handle_t, unsigned int, void * );

static NTSTATUS handle_unix_call( DWORD64 *rsp )
{
    struct stack_layout {
        unixlib_handle_t handle;
        UINT32 id;
        ULONG32 args;
    } *stack = (struct stack_layout *)(*rsp);

    *rsp += sizeof(struct stack_layout);

    return p__wine_unix_call( stack->handle, stack->id, ULongToPtr( stack->args ) );
}

static void prep_jit_enter(void)
{
    LONG expected_val, new_val;
    LONG *control_word = (LONG *)&NtCurrentTeb()->TlsSlots[FEXCORE_TLS_CONTROL_WORD];

    /* Spin until CONTROL_PAUSED is unset, setting CONTROL_IN_JIT when that occurs */
    do
    {
        expected_val = *control_word & ~CONTROL_PAUSED;
        new_val = (expected_val | CONTROL_IN_JIT) & ~CONTROL_CPU_AREA_DIRTY;
    }
    while (InterlockedCompareExchange( control_word, new_val, expected_val ) != expected_val);

    /* If the CPU area is dirty, flush it to the JIT context before reentry */
    if (expected_val & CONTROL_CPU_AREA_DIRTY)
    {
        I386_CONTEXT *wow_context;
        RtlWow64GetCurrentCpuArea( NULL, (void **)&wow_context, NULL );
        pho_thread_set_context( NtCurrentTeb(), (DWORD64)get_wow_teb( NtCurrentTeb() ), wow_context );
    }
}

static void prep_jit_leave(void)
{
    LONG expected_val, new_val;
    LONG *control_word = (LONG *)&NtCurrentTeb()->TlsSlots[FEXCORE_TLS_CONTROL_WORD];

    /* Unset CONTROL_IN_JIT and set CONTROL_FEX_CONTEXT_DIRTY so that BTGetThreadContext knows to use the FEX context
     * rather than the CPU area */
    do
    {
        expected_val = *control_word;
        new_val = (expected_val & ~CONTROL_IN_JIT) | CONTROL_FEX_CONTEXT_DIRTY;
    }
    while (InterlockedCompareExchange( control_word, new_val, expected_val ) != expected_val);
}

static void syscall_callback( DWORD64 *rip, DWORD64 *rax, DWORD64 *rsp )
{
    NTSTATUS ret;
    DWORD64 entry_rip = *rip, entry_rax = *rax;
    DWORD64 new_rip = *(UINT32 *)(*rsp); /* Return address from the stack */
    DWORD64 new_rsp = *rsp + 4; /* Stack pointer after popping return address */

    if (entry_rip == (DWORD64)&unxcode)
    {
        // NOTE: this will break if there are any infinitely-blocking unix calls or unix calls that perform alertable waits
        ret = handle_unix_call( &new_rsp );
    }
    else if (entry_rip == (DWORD64)&bopcode)
    {
        /* APCs end up calling into the JIT from Wow64SystemService, and since the FEX return stack
         * pointer is stored in TLS, the reentrant call ends up overwriting the callers stored
         * return stack location. Stash it here to avoid that breaking returns used in thread suspend */
        DWORD64 *returning_stack_ptr = pho_thread_get_returning_stack_ptr();
        DWORD64 stashed_stack_ptr = *returning_stack_ptr;

        prep_jit_leave();
        ret = Wow64SystemServiceEx( (UINT)entry_rax, (UINT *)(new_rsp + 4) );
        prep_jit_enter();

        *returning_stack_ptr = stashed_stack_ptr;
    }

    /* If a new context has been set, use it directly and don't return to the syscall caller */
    if (*rip == entry_rip) {
        *rip = new_rip;
        *rsp = new_rsp;
        *rax = (UINT32)ret;
    }
}


/* From dlls/ntdll/unix/system.c */
#define AUTH	0x68747541	/* "Auth" */
#define ENTI	0x69746e65	/* "enti" */
#define CAMD	0x444d4163	/* "cAMD" */

#define GENU	0x756e6547	/* "Genu" */
#define INEI	0x49656e69	/* "ineI" */
#define NTEL	0x6c65746e	/* "ntel" */

static void get_cpuinfo( SYSTEM_CPU_INFORMATION *info )
{
    UINT32 regs[4], regs2[4], regs3[4];
    ULONGLONG features;

    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;

    /* We're at least a 386 */
    features = CPU_FEATURE_VME | CPU_FEATURE_X86 | CPU_FEATURE_PGE;
    info->ProcessorLevel = 3;

    pho_run_cpuid_function( 0x00000000, 0, regs );  /* get standard cpuid level and vendor name */
    if (regs[0]>=0x00000001)   /* Check for supported cpuid version */
    {
        pho_run_cpuid_function( 0x00000001, 0, regs2 ); /* get cpu features */
        if (regs2[3] & (1 << 3 )) features |= CPU_FEATURE_PSE;
        if (regs2[3] & (1 << 4 )) features |= CPU_FEATURE_TSC;
        if (regs2[3] & (1 << 6 )) features |= CPU_FEATURE_PAE;
        if (regs2[3] & (1 << 8 )) features |= CPU_FEATURE_CX8;
        if (regs2[3] & (1 << 11)) features |= CPU_FEATURE_SEP;
        if (regs2[3] & (1 << 12)) features |= CPU_FEATURE_MTRR;
        if (regs2[3] & (1 << 15)) features |= CPU_FEATURE_CMOV;
        if (regs2[3] & (1 << 16)) features |= CPU_FEATURE_PAT;
        if (regs2[3] & (1 << 23)) features |= CPU_FEATURE_MMX;
        if (regs2[3] & (1 << 24)) features |= CPU_FEATURE_FXSR;
        if (regs2[3] & (1 << 25)) features |= CPU_FEATURE_SSE;
        if (regs2[3] & (1 << 26)) features |= CPU_FEATURE_SSE2;
        if (regs2[2] & (1 << 0 )) features |= CPU_FEATURE_SSE3;
        if (regs2[2] & (1 << 9 )) features |= CPU_FEATURE_SSSE3;
        if (regs2[2] & (1 << 13)) features |= CPU_FEATURE_CX128;
        if (regs2[2] & (1 << 19)) features |= CPU_FEATURE_SSE41;
        if (regs2[2] & (1 << 20)) features |= CPU_FEATURE_SSE42;
        if (regs2[2] & (1 << 27)) features |= CPU_FEATURE_XSAVE;
        if (regs2[2] & (1 << 28)) features |= CPU_FEATURE_AVX;
        if ((regs2[3] & (1 << 26)) && (regs2[3] & (1 << 24))) /* has SSE2 and FXSAVE/FXRSTOR */
            features |= CPU_FEATURE_DAZ;

        if (regs[0] >= 0x00000007)
        {
            pho_run_cpuid_function( 0x00000007, 0, regs3 ); /* get extended features */
            if (regs3[1] & (1 << 5)) features |= CPU_FEATURE_AVX2;
        }

        if (regs[1] == AUTH && regs[3] == ENTI && regs[2] == CAMD)
        {
            info->ProcessorLevel = (regs2[0] >> 8) & 0xf; /* family */
            if (info->ProcessorLevel == 0xf)  /* AMD says to add the extended family to the family if family is 0xf */
                info->ProcessorLevel += (regs2[0] >> 20) & 0xff;

            /* repack model and stepping to make a "revision" */
            info->ProcessorRevision  = ((regs2[0] >> 16) & 0xf) << 12; /* extended model */
            info->ProcessorRevision |= ((regs2[0] >> 4 ) & 0xf) << 8;  /* model          */
            info->ProcessorRevision |= regs2[0] & 0xf;                 /* stepping       */

            pho_run_cpuid_function( 0x80000000, 0, regs );  /* get vendor cpuid level */
            if (regs[0] >= 0x80000001)
            {
                pho_run_cpuid_function( 0x80000001, 0, regs2 );  /* get vendor features */
                if (regs2[2] & (1 << 2))   features |= CPU_FEATURE_VIRT;
                if (regs2[3] & (1 << 20))  features |= CPU_FEATURE_NX;
                if (regs2[3] & (1 << 27))  features |= CPU_FEATURE_TSC;
                if (regs2[3] & (1u << 31)) features |= CPU_FEATURE_3DNOW;
            }
        }
        else if (regs[1] == GENU && regs[3] == INEI && regs[2] == NTEL)
        {
            info->ProcessorLevel = ((regs2[0] >> 8) & 0xf) + ((regs2[0] >> 20) & 0xff); /* family + extended family */
            if(info->ProcessorLevel == 15) info->ProcessorLevel = 6;

            /* repack model and stepping to make a "revision" */
            info->ProcessorRevision  = ((regs2[0] >> 16) & 0xf) << 12; /* extended model */
            info->ProcessorRevision |= ((regs2[0] >> 4 ) & 0xf) << 8;  /* model          */
            info->ProcessorRevision |= regs2[0] & 0xf;                 /* stepping       */

            if(regs2[2] & (1 << 5))  features |= CPU_FEATURE_VIRT;
            if(regs2[3] & (1 << 21)) features |= CPU_FEATURE_DS;

            pho_run_cpuid_function( 0x80000000, 0, regs );  /* get vendor cpuid level */
            if (regs[0] >= 0x80000001)
            {
                pho_run_cpuid_function( 0x80000001, 0, regs2 );  /* get vendor features */
                if (regs2[3] & (1 << 20)) features |= CPU_FEATURE_NX;
                if (regs2[3] & (1 << 27)) features |= CPU_FEATURE_TSC;
            }
        }
        else
        {
            info->ProcessorLevel = (regs2[0] >> 8) & 0xf; /* family */

            /* repack model and stepping to make a "revision" */
            info->ProcessorRevision = ((regs2[0] >> 4 ) & 0xf) << 8;  /* model    */
            info->ProcessorRevision |= regs2[0] & 0xf;                /* stepping */
        }
    }
    info->ProcessorFeatureBits = features;
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
    LOAD_FUNCPTR(ho_reconstruct_wow_context);
    LOAD_FUNCPTR(ho_unaligned_access_handler);
    LOAD_FUNCPTR(ho_address_in_jit);
    LOAD_FUNCPTR(ho_request_thread_return);
    LOAD_FUNCPTR(ho_thread_init);
    LOAD_FUNCPTR(ho_thread_terminate);
    LOAD_FUNCPTR(ho_thread_set_context);
    LOAD_FUNCPTR(ho_thread_get_context);
    LOAD_FUNCPTR(ho_thread_get_context);
    LOAD_FUNCPTR(ho_run_cpuid_function);
    LOAD_FUNCPTR(ho_thread_get_returning_stack_ptr);
#undef LOAD_FUNCPTR

    RtlInitUnicodeString( &str, L"ntdll.dll" );
    LdrGetDllHandle( NULL, 0, &str, &module );
    p__wine_unix_call = RtlFindExportedRoutineByName( module, "__wine_unix_call" );

    RtlInitializeCriticalSection( &thread_suspend_cs );
    pho_init( &syscall_callback );

    get_cpuinfo( &cpu_info );
    return STATUS_SUCCESS;
}



/**********************************************************************
 *           BTCpuIsProcessorFeaturePresent  (xtajit.@)
 */
BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent( UINT feature )
{
    switch (feature)
    {
        case PF_COMPARE_EXCHANGE_DOUBLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_CX8);
        case PF_MMX_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_MMX);
        case PF_XMMI_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_SSE);
        case PF_3DNOW_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_3DNOW);
        case PF_RDTSC_INSTRUCTION_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_TSC);
        case PF_PAE_ENABLED:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_PAE);
        case PF_XMMI64_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_SSE2);
        case PF_SSE3_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_SSE3);
        case PF_SSSE3_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_SSSE3);
        case PF_XSAVE_ENABLED:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_XSAVE);
        case PF_COMPARE_EXCHANGE128:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_CX128);
        case PF_SSE_DAZ_MODE_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_DAZ);
        case PF_NX_ENABLED:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_NX);
        case PF_SECOND_LEVEL_ADDRESS_TRANSLATION:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_2NDLEV);
        case PF_VIRT_FIRMWARE_ENABLED:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_VIRT);
        case PF_RDWRFSGSBASE_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_RDFS);
        case PF_FASTFAIL_AVAILABLE:
            return TRUE;
        case PF_SSE4_1_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_SSE41);
        case PF_SSE4_2_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_SSE42);
        case PF_AVX_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_AVX);
        case PF_AVX2_INSTRUCTIONS_AVAILABLE:
            return !!(cpu_info.ProcessorFeatureBits & CPU_FEATURE_AVX2);
        default:
            ERR( "Unknown CPU feature: %x\n", feature);
            return FALSE;
    }
}

/**********************************************************************
 *           BTCpuUpdateProcessorInformation  (xtajit.@)
 */
BOOLEAN WINAPI BTCpuUpdateProcessorInformation( SYSTEM_CPU_INFORMATION *info )
{
    info->ProcessorArchitecture = cpu_info.ProcessorArchitecture;
    info->ProcessorLevel = cpu_info.ProcessorLevel;
    info->ProcessorRevision = cpu_info.ProcessorRevision;
    info->ProcessorFeatureBits = cpu_info.ProcessorFeatureBits;
    return TRUE;
}

/**********************************************************************
 *           BTCpuSimulate  (xtajit.@)
 */
void WINAPI BTCpuSimulate(void)
{
    CONTEXT entry_context;
    CONTEXT **tls_entry_context = (CONTEXT **)&NtCurrentTeb()->TlsSlots[FEXCORE_TLS_ENTRY_CTX];

    RtlCaptureContext( &entry_context );

    /* APC handling calls BTCpuSimulate from syscalls and then use NtContinue to return to the previous context,
     * to avoid the saved context being clobbered in this case only save the entry context highest in the stack */
    if (!*tls_entry_context ||  (*tls_entry_context)->Sp <= entry_context.Sp) *tls_entry_context = &entry_context;

    while (1) {
        prep_jit_enter();
        pho_run();
        prep_jit_leave();
    }
}


/**********************************************************************
 *            BTCpuSuspendLocalThread (xtajit.@)
 */
NTSTATUS WINAPI BTCpuSuspendLocalThread( HANDLE thread, ULONG *count )
{
    THREAD_BASIC_INFORMATION tbi;
    TEB *thread_teb;
    LONG *control_word;
    LONG expected_val, new_val;
    CONTEXT tmp_context;
    NTSTATUS ret = NtQueryInformationThread( thread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL );
    if (ret) return ret;

    thread_teb = tbi.TebBaseAddress;
    control_word = (LONG *)&thread_teb->TlsSlots[FEXCORE_TLS_CONTROL_WORD];

    TRACE( "Suspending thread: %p\n", thread_teb->ClientId.UniqueThread );

    RtlEnterCriticalSection( &thread_suspend_cs );
    InterlockedOr( control_word, CONTROL_PAUSED );

    /* If CONTROL_IN_JIT is unset at this point, then it can never be set (and thus the JIT cannot
     * be reentered) as CONTROL_PAUSED has been set, as such, while this may redundantly request
     * returns in rare cases it will never miss them */
    if (*control_word & CONTROL_IN_JIT)
    {
        TRACE( "Thread %p is in JIT, polling for return\n", thread_teb->ClientId.UniqueThread );
        pho_request_thread_return( thread_teb );
    }

    /* Spin until the JIT returns */
    while (InterlockedOr( control_word, 0 ) & CONTROL_IN_JIT);

    /* The JIT has now returned and the context stored in the thread's CPU area is up-to-date */
    ret = NtSuspendThread( thread, count );
    if (ret) goto end;

    tmp_context.ContextFlags = CONTEXT_INTEGER;

    /* NtSuspendThread may return before the thread is actually suspended, so a sync operation
     * like NtGetContextThread needs to be called to ensure it is before we unset CONTROL_PAUSED */
    (void)NtGetContextThread( thread, &tmp_context );

    /* If the context is dirty after leaving the JIT, flush it to the CPU area. Also mark the CPU area
     * as dirty, to force the JIT context to be restored from it on entry */
    do
    {
        expected_val = *control_word;
        new_val = (expected_val & ~CONTROL_FEX_CONTEXT_DIRTY) | CONTROL_CPU_AREA_DIRTY;
    }
    while (InterlockedCompareExchange( control_word, new_val, expected_val ) != expected_val);

    if (expected_val & CONTROL_FEX_CONTEXT_DIRTY)
    {
        I386_CONTEXT tmp_wow_context;
        tmp_wow_context.ContextFlags = CONTEXT_I386_FULL | CONTEXT_I386_EXTENDED_REGISTERS;
        pho_thread_get_context( thread_teb, &tmp_wow_context );
        ret = RtlWow64SetThreadContext( thread, &tmp_wow_context );
        if (ret) goto end;
    }

end:
    TRACE( "Thread suspended: %p\n", thread_teb->ClientId.UniqueThread );

    if ( *control_word & CONTROL_IN_JIT ) ERR( "Suspend failed!\n" );

    /* Now the thread is suspended on the host, unset CONTROL_PAUSED so that NtResumeThread will
     * continue execution in the JIT */
    InterlockedAnd( control_word, ~CONTROL_PAUSED );
    RtlLeaveCriticalSection( &thread_suspend_cs );

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
    NTSTATUS ret = NtQueryInformationThread( thread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL );
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
NTSTATUS WINAPI BTCpuGetContext( HANDLE thread, HANDLE process, void *unknown, I386_CONTEXT *context )
{
    LONG *control_word;
    TEB *thread_teb;
    THREAD_BASIC_INFORMATION tbi;
    NTSTATUS ret = NtQueryInformationThread( thread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL );
    if (ret) return ret;

    thread_teb = tbi.TebBaseAddress;
    control_word = (LONG *)&thread_teb->TlsSlots[FEXCORE_TLS_CONTROL_WORD];

    /* Either the thread is suspended or the thread is the current thread, either way we can assume
     * nothing will race these control word reads */
    if (*control_word & CONTROL_FEX_CONTEXT_DIRTY)
    {
        pho_thread_get_context( thread_teb, context );
        return STATUS_SUCCESS;
    }
    else
    {
        return RtlWow64GetThreadContext( thread, context );
    }
}


/**********************************************************************
 *           BTCpuSetContext  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuSetContext( HANDLE thread, HANDLE process, void *unknown, I386_CONTEXT *context )
{
    I386_CONTEXT tmp_context;
    LONG *control_word;
    TEB *thread_teb;
    THREAD_BASIC_INFORMATION tbi;
    NTSTATUS ret = NtQueryInformationThread( thread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL );
    if (ret) return ret;

    thread_teb = tbi.TebBaseAddress;
    control_word = (LONG *)&thread_teb->TlsSlots[FEXCORE_TLS_CONTROL_WORD];
    tmp_context.ContextFlags = CONTEXT_I386_FULL | CONTEXT_I386_EXTENDED_REGISTERS;

    /* Either the thread is suspended or the thread is the current thread, either way we can assume
     * nothing will race these control word reads */
    if (*control_word & CONTROL_FEX_CONTEXT_DIRTY)
    {
        /* Merge in any unwritten context changes to the CPU area first, as the new context may only be partial */
        pho_thread_get_context( thread_teb, &tmp_context );
        ret = RtlWow64SetThreadContext( thread, &tmp_context );
        if (ret) return ret;

        /* While reads are safe, writes are not, as SuspendThread may be called on an already suspended thread and it would
         * perform interlocked writes in such a case (see BTCpuSuspendLocalThread) */
        InterlockedAnd( control_word, ~CONTROL_FEX_CONTEXT_DIRTY );
    }

    /* Merge the input context into the CPU area then pass the full context into the JIT */
    /* TODO: maybe just merge on jit side? */
    ret = RtlWow64SetThreadContext( thread, context );
    if (ret) return ret;

    ret = RtlWow64GetThreadContext( thread, &tmp_context );
    if (ret) return ret;

    pho_thread_set_context( thread_teb, (DWORD64)get_wow_teb( thread_teb ), &tmp_context );
    return STATUS_SUCCESS;
}

/**********************************************************************
 *           BTCpuResetToConsistentState  (xtajit.@)
 */
NTSTATUS WINAPI BTCpuResetToConsistentState( EXCEPTION_POINTERS *ptrs )
{
    CONTEXT *context = ptrs->ContextRecord;
    EXCEPTION_RECORD *exception = ptrs->ExceptionRecord;
    I386_CONTEXT wow_context;
    CONTEXT *entry_context = NtCurrentTeb()->TlsSlots[FEXCORE_TLS_ENTRY_CTX];
    LONG *control_word = (LONG *)&NtCurrentTeb()->TlsSlots[FEXCORE_TLS_CONTROL_WORD];

    if (exception->ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT && pho_unaligned_access_handler( context ))
    {
        TRACE("Handled unaligned atomic\n");
        NtContinue( context, FALSE );
    }

    if (!pho_address_in_jit( context->Pc )) return STATUS_SUCCESS;

    FIXME( "Reconstructing context\n" );
    pho_reconstruct_wow_context( &wow_context, context );
    TRACE( "pc: %#llx eip: %#lx\n", context->Pc, wow_context.Eip );

    BTCpuSetContext( GetCurrentThread(), GetCurrentProcess(), NULL, &wow_context );

    InterlockedAnd( control_word, ~CONTROL_IN_JIT );

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
