/*
 * ARM signal handling routines
 *
 * Copyright 2002 Marcus Meissner, SuSE Linux AG
 * Copyright 2010-2013, 2015 André Hentschel
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

#ifdef __arm__

#include <stdlib.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/exception.h"
#include "ntdll_misc.h"
#include "wine/debug.h"
#include "ntsyscalls.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);
WINE_DECLARE_DEBUG_CHANNEL(relay);

/* layering violation: the setjmp buffer is defined in msvcrt, but used by RtlUnwindEx */
struct MSVCRT_JUMP_BUFFER
{
    unsigned long Frame;
    unsigned long R4;
    unsigned long R5;
    unsigned long R6;
    unsigned long R7;
    unsigned long R8;
    unsigned long R9;
    unsigned long R10;
    unsigned long R11;
    unsigned long Sp;
    unsigned long Pc;
    unsigned long Fpscr;
    unsigned long long D[8];
};

/*******************************************************************
 *         syscalls
 */
#define SYSCALL_ENTRY(id,name,args) __ASM_SYSCALL_FUNC( id, name, args )
ALL_SYSCALLS32
DEFINE_SYSCALL_HELPER32()
#undef SYSCALL_ENTRY


/**************************************************************************
 *		__chkstk (NTDLL.@)
 *
 * Incoming r4 contains words to allocate, converting to bytes then return
 */
__ASM_GLOBAL_FUNC( __chkstk, "lsl r4, r4, #2\n\t"
                             "bx lr" )

/***********************************************************************
 *		RtlCaptureContext (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlCaptureContext,
                    "str r1, [r0, #0x8]\n\t"   /* context->R1 */
                    "mov r1, #0x0200000\n\t"   /* CONTEXT_ARM */
                    "add r1, r1, #0x7\n\t"     /* CONTEXT_CONTROL|CONTEXT_INTEGER|CONTEXT_FLOATING_POINT */
                    "str r1, [r0]\n\t"         /* context->ContextFlags */
                    "str SP, [r0, #0x38]\n\t"  /* context->Sp */
                    "str LR, [r0, #0x40]\n\t"  /* context->Pc */
                    "mrs r1, CPSR\n\t"
                    "bfi r1, lr, #5, #1\n\t"   /* Thumb bit */
                    "str r1, [r0, #0x44]\n\t"  /* context->Cpsr */
                    "mov r1, #0\n\t"
                    "str r1, [r0, #0x4]\n\t"   /* context->R0 */
                    "str r1, [r0, #0x3c]\n\t"  /* context->Lr */
                    "add r0, #0x0c\n\t"
                    "stm r0, {r2-r12}\n\t"     /* context->R2..R12 */
#ifndef __SOFTFP__
                    "add r0, #0x44\n\t"        /* 0x50 - 0x0c */
                    "vstm r0, {d0-d15}\n\t"    /* context->D0-D15 */
#endif
                    "bx lr" )

__ASM_GLOBAL_FUNC( KiUserExceptionDispatcher,
                   __ASM_SEH(".seh_custom 0xee,0x02\n\t")  /* MSFT_OP_CONTEXT */
                   __ASM_SEH(".seh_endprologue\n\t")
                   __ASM_EHABI(".save {sp}\n\t") /* Restore Sp last */
                   __ASM_EHABI(".pad #-(0x80 + 0x0c + 0x0c)\n\t") /* Move back across D0-D15, Cpsr, Fpscr, Padding, Pc, Lr and Sp */
                   __ASM_EHABI(".vsave {d8-d15}\n\t")
                   __ASM_EHABI(".pad #0x40\n\t") /* Skip past D0-D7 */
                   __ASM_EHABI(".pad #0x0c\n\t") /* Skip past Cpsr, Fpscr and Padding */
                   __ASM_EHABI(".save {lr, pc}\n\t")
                   __ASM_EHABI(".pad #0x08\n\t") /* Skip past R12 and Sp - Sp is restored last */
                   __ASM_EHABI(".save {r4-r11}\n\t")
                   __ASM_EHABI(".pad #0x14\n\t") /* Skip past ContextFlags and R0-R3 */
                   "add r0, sp, #0x1a0\n\t"     /* rec (context + 1) */
                   "mov r1, sp\n\t"             /* context */
                   "bl " __ASM_NAME("dispatch_exception") "\n\t"
                   "udf #1" )


/*******************************************************************
 *		KiUserApcDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( KiUserApcDispatcher,
                   __ASM_SEH(".seh_custom 0xee,0x02\n\t")  /* MSFT_OP_CONTEXT */
                   "nop\n\t"
                   __ASM_SEH(".seh_stackalloc 0x18\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   __ASM_EHABI(".save {sp}\n\t") /* Restore Sp last */
                   __ASM_EHABI(".pad #-(0x80 + 0x0c + 0x0c)\n\t") /* Move back across D0-D15, Cpsr, Fpscr, Padding, Pc, Lr and Sp */
                   __ASM_EHABI(".vsave {d8-d15}\n\t")
                   __ASM_EHABI(".pad #0x40\n\t") /* Skip past D0-D7 */
                   __ASM_EHABI(".pad #0x0c\n\t") /* Skip past Cpsr, Fpscr and Padding */
                   __ASM_EHABI(".save {lr, pc}\n\t")
                   __ASM_EHABI(".pad #0x08\n\t") /* Skip past R12 and Sp - Sp is restored last */
                   __ASM_EHABI(".save {r4-r11}\n\t")
                   __ASM_EHABI(".pad #0x2c\n\t") /* Skip past args, ContextFlags and R0-R3 */
                   "ldr r0, [sp, #0x04]\n\t"      /* arg1 */
                   "ldr r1, [sp, #0x08]\n\t"      /* arg2 */
                   "ldr r2, [sp, #0x0c]\n\t"      /* arg3 */
                   "ldr ip, [sp]\n\t"             /* func */
                   "blx ip\n\t"
                   "add r0, sp, #0x18\n\t"        /* context */
                   "ldr r1, [sp, #0x10]\n\t"      /* alertable */
                   "bl " __ASM_NAME("NtContinue") "\n\t"
                   "udf #1" )


/*******************************************************************
 *		KiUserCallbackDispatcher (NTDLL.@)
 */
void WINAPI dispatch_callback( void *args, ULONG len, ULONG id )
{
    NTSTATUS status;

    __TRY
    {
        NTSTATUS (WINAPI *func)(void *, ULONG) = ((void **)NtCurrentTeb()->Peb->KernelCallbackTable)[id];
        status = NtCallbackReturn( NULL, 0, func( args, len ));
    }
    __EXCEPT_ALL
    {
        ERR_(seh)( "ignoring exception\n" );
        status = NtCallbackReturn( 0, 0, 0 );
    }
    __ENDTRY

    RtlRaiseStatus( status );
}
__ASM_GLOBAL_FUNC( KiUserCallbackDispatcher,
                   __ASM_SEH(".seh_custom 0xee,0x01\n\t")  /* MSFT_OP_MACHINE_FRAME */
                   "nop\n\t"
                   __ASM_SEH(".seh_save_regs {lr}\n\t")
                   "nop\n\t"
                   __ASM_SEH(".seh_stackalloc 0xc\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")
                   __ASM_EHABI(".save {sp, pc}\n\t")
                   __ASM_EHABI(".save {lr}\n\t")
                   __ASM_EHABI(".pad #0x0c\n\t")
                   "ldr r0, [sp]\n\t"             /* args */
                   "ldr r1, [sp, #0x04]\n\t"      /* len */
                   "ldr r2, [sp, #0x08]\n\t"      /* id */
                   "bl " __ASM_NAME("dispatch_callback") "\n\t"
                   "udf #1" )


/***********************************************************************
 * Definitions for Win32 unwind tables
 */

struct unwind_info
{
    DWORD function_length : 18;
    DWORD version : 2;
    DWORD x : 1;
    DWORD e : 1;
    DWORD f : 1;
    DWORD epilog : 5;
    DWORD codes : 4;
};

struct unwind_info_ext
{
    WORD epilog;
    BYTE codes;
    BYTE reserved;
};

struct unwind_info_epilog
{
    DWORD offset : 18;
    DWORD res : 2;
    DWORD cond : 4;
    DWORD index : 8;
};

static const BYTE unwind_code_len[256] =
{
/* 00 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 20 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 40 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 60 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 80 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* a0 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* c0 */ 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* e0 */ 1,1,1,1,1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,4,3,4,1,1,1,1,1
};

static const BYTE unwind_instr_len[256] =
{
/* 00 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* 20 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* 40 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* 60 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
/* 80 */ 4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
/* a0 */ 4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
/* c0 */ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,4,4,4,4,4,4,4,4,
/* e0 */ 4,4,4,4,4,4,4,4,4,4,4,4,2,2,0,4,0,0,0,0,0,4,4,2,2,4,4,2,4,2,4,0
};

/***********************************************************************
 *           get_sequence_len
 */
static unsigned int get_sequence_len( BYTE *ptr, BYTE *end, int include_end )
{
    unsigned int ret = 0;

    while (ptr < end)
    {
        if (*ptr >= 0xfd)
        {
            if (*ptr <= 0xfe && include_end)
                ret += unwind_instr_len[*ptr];
            break;
        }
        ret += unwind_instr_len[*ptr];
        ptr += unwind_code_len[*ptr];
    }
    return ret;
}


/***********************************************************************
 *           pop_regs_mask
 */
static void pop_regs_mask( int mask, CONTEXT *context,
                           KNONVOLATILE_CONTEXT_POINTERS *ptrs )
{
    int i;
    for (i = 0; i <= 12; i++)
    {
        if (!(mask & (1 << i))) continue;
        if (ptrs && i >= 4 && i <= 11) (&ptrs->R4)[i - 4] = (DWORD *)context->Sp;
        if (i >= 4) (&context->R0)[i] = *(DWORD *)context->Sp;
        context->Sp += 4;
    }
}


/***********************************************************************
 *           pop_regs_range
 */
static void pop_regs_range( int last, CONTEXT *context,
                            KNONVOLATILE_CONTEXT_POINTERS *ptrs )
{
    int i;
    for (i = 4; i <= last; i++)
    {
        if (ptrs) (&ptrs->R4)[i - 4] = (DWORD *)context->Sp;
        (&context->R0)[i] = *(DWORD *)context->Sp;
        context->Sp += 4;
    }
}


/***********************************************************************
 *           pop_lr
 */
static void pop_lr( int increment, CONTEXT *context,
                    KNONVOLATILE_CONTEXT_POINTERS *ptrs )
{
    if (ptrs) ptrs->Lr = (DWORD *)context->Sp;
    context->Lr = *(DWORD *)context->Sp;
    context->Sp += increment;
}


/***********************************************************************
 *           pop_fpregs_range
 */
static void pop_fpregs_range( int first, int last, CONTEXT *context,
                              KNONVOLATILE_CONTEXT_POINTERS *ptrs )
{
    int i;
    for (i = first; i <= last; i++)
    {
        if (ptrs && i >= 8 && i <= 15) (&ptrs->D8)[i - 8] = (ULONGLONG *)context->Sp;
        context->D[i] = *(ULONGLONG *)context->Sp;
        context->Sp += 8;
    }
}


/***********************************************************************
 *           ms_opcode
 */
static void ms_opcode( BYTE opcode, CONTEXT *context,
                       KNONVOLATILE_CONTEXT_POINTERS *ptrs )
{
    switch (opcode)
    {
    case 1:  /* MSFT_OP_MACHINE_FRAME */
        context->Pc = ((DWORD *)context->Sp)[1];
        context->Sp = ((DWORD *)context->Sp)[0];
        break;
    case 2:  /* MSFT_OP_CONTEXT */
    {
        int i;
        CONTEXT *src = (CONTEXT *)context->Sp;

        *context = *src;
        if (!ptrs) break;
        for (i = 0; i < 8; i++) (&ptrs->R4)[i] = &src->R4 + i;
        ptrs->Lr = &src->Lr;
        for (i = 0; i < 8; i++) (&ptrs->D8)[i] = &src->D[i + 8];
        break;
    }
    default:
        WARN( "unsupported code %02x\n", opcode );
        break;
    }
}


/***********************************************************************
 *           process_unwind_codes
 */
static void process_unwind_codes( BYTE *ptr, BYTE *end, CONTEXT *context,
                                  KNONVOLATILE_CONTEXT_POINTERS *ptrs, int skip )
{
    unsigned int val, len;
    unsigned int i;

    /* skip codes */
    while (ptr < end && skip)
    {
        if (*ptr >= 0xfd) break;
        skip -= unwind_instr_len[*ptr];
        ptr += unwind_code_len[*ptr];
    }

    while (ptr < end)
    {
        len = unwind_code_len[*ptr];
        if (ptr + len > end) break;
        val = 0;
        for (i = 0; i < len; i++)
            val = (val << 8) | ptr[i];

        if (*ptr <= 0x7f)      /* add sp, sp, #x */
            context->Sp += 4 * (val & 0x7f);
        else if (*ptr <= 0xbf) /* pop {r0-r12,lr} */
        {
            pop_regs_mask( val & 0x1fff, context, ptrs );
            if (val & 0x2000)
                pop_lr( 4, context, ptrs );
        }
        else if (*ptr <= 0xcf) /* mov sp, rX */
            context->Sp = (&context->R0)[val & 0x0f];
        else if (*ptr <= 0xd7) /* pop {r4-rX,lr} */
        {
            pop_regs_range( (val & 0x03) + 4, context, ptrs );
            if (val & 0x04)
                pop_lr( 4, context, ptrs );
        }
        else if (*ptr <= 0xdf) /* pop {r4-rX,lr} */
        {
            pop_regs_range( (val & 0x03) + 8, context, ptrs );
            if (val & 0x04)
                pop_lr( 4, context, ptrs );
        }
        else if (*ptr <= 0xe7) /* vpop {d8-dX} */
            pop_fpregs_range( 8, (val & 0x07) + 8, context, ptrs );
        else if (*ptr <= 0xeb) /* add sp, sp, #x */
            context->Sp += 4 * (val & 0x3ff);
        else if (*ptr <= 0xed) /* pop {r0-r12,lr} */
        {
            pop_regs_mask( val & 0xff, context, ptrs );
            if (val & 0x100)
                pop_lr( 4, context, ptrs );
        }
        else if (*ptr <= 0xee) /* Microsoft-specific 0x00-0x0f, Available 0x10-0xff */
            ms_opcode( val & 0xff, context, ptrs );
        else if (*ptr <= 0xef && ((val & 0xff) <= 0x0f)) /* ldr lr, [sp], #x */
            pop_lr( 4 * (val & 0x0f), context, ptrs );
        else if (*ptr <= 0xf4) /* Available */
            WARN( "unsupported code %02x\n", *ptr );
        else if (*ptr <= 0xf5) /* vpop {dS-dE} */
            pop_fpregs_range( (val & 0xf0) >> 4, (val & 0x0f), context, ptrs );
        else if (*ptr <= 0xf6) /* vpop {dS-dE} */
            pop_fpregs_range( ((val & 0xf0) >> 4) + 16, (val & 0x0f) + 16, context, ptrs );
        else if (*ptr == 0xf7 || *ptr == 0xf9) /* add sp, sp, #x */
            context->Sp += 4 * (val & 0xffff);
        else if (*ptr == 0xf8 || *ptr == 0xfa) /* add sp, sp, #x */
            context->Sp += 4 * (val & 0xffffff);
        else if (*ptr <= 0xfc)  /* nop */
            /* nop */ ;
        else                    /* end */
            break;

        ptr += len;
    }
}


/***********************************************************************
 *           unwind_packed_data
 */
static void *unwind_packed_data( ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION *func,
                                 CONTEXT *context, KNONVOLATILE_CONTEXT_POINTERS *ptrs )
{
    int i, pos = 0;
    int pf = 0, ef = 0, fpoffset = 0, stack = func->StackAdjust;
    int prologue_regmask = 0;
    int epilogue_regmask = 0;
    unsigned int offset, len;
    BYTE prologue[10], *prologue_end, epilogue[20], *epilogue_end;

    TRACE( "function %lx-%lx: len=%#x flag=%x ret=%u H=%u reg=%u R=%u L=%u C=%u stackadjust=%x\n",
           base + func->BeginAddress, base + func->BeginAddress + func->FunctionLength * 2,
           func->FunctionLength, func->Flag, func->Ret,
           func->H, func->Reg, func->R, func->L, func->C, func->StackAdjust );

    offset = (pc - base) - func->BeginAddress;
    if (func->StackAdjust >= 0x03f4)
    {
        pf = func->StackAdjust & 0x04;
        ef = func->StackAdjust & 0x08;
        stack = (func->StackAdjust & 3) + 1;
    }

    if (!func->R || pf)
    {
        int first = 4, last = func->Reg + 4;
        if (pf)
        {
            first = (~func->StackAdjust) & 3;
            if (func->R)
                last = 3;
        }
        for (i = first; i <= last; i++)
            prologue_regmask |= 1 << i;
        fpoffset = last + 1 - first;
    }

    if (!func->R || ef)
    {
        int first = 4, last = func->Reg + 4;
        if (ef)
        {
            first = (~func->StackAdjust) & 3;
            if (func->R)
                last = 3;
        }
        for (i = first; i <= last; i++)
            epilogue_regmask |= 1 << i;
    }

    if (func->C)
    {
        prologue_regmask |= 1 << 11;
        epilogue_regmask |= 1 << 11;
    }

    if (func->L)
    {
        prologue_regmask |= 1 << 14; /* lr */
        if (func->Ret != 0)
            epilogue_regmask |= 1 << 14; /* lr */
        else if (!func->H)
            epilogue_regmask |= 1 << 15; /* pc */
    }

    /* Synthesize prologue opcodes */
    if (stack && !pf)
    {
        if (stack <= 0x7f)
        {
            prologue[pos++] = stack; /* sub sp, sp, #x */
        }
        else
        {
            prologue[pos++] = 0xe8 | (stack >> 8); /* sub.w sp, sp, #x */
            prologue[pos++] = stack & 0xff;
        }
    }

    if (func->R && func->Reg != 7)
        prologue[pos++] = 0xe0 | func->Reg; /* vpush {d8-dX} */

    if (func->C && fpoffset == 0)
        prologue[pos++] = 0xfb; /* mov r11, sp - handled as nop16 */
    else if (func->C)
        prologue[pos++] = 0xfc; /* add r11, sp, #x - handled as nop32 */

    if (prologue_regmask & 0xf00) /* r8-r11 set */
    {
        int bitmask = prologue_regmask & 0x1fff;
        if (prologue_regmask & (1 << 14)) /* lr */
            bitmask |= 0x2000;
        prologue[pos++] = 0x80 | (bitmask >> 8); /* push.w {r0-r12,lr} */
        prologue[pos++] = bitmask & 0xff;
    }
    else if (prologue_regmask) /* r0-r7, lr set */
    {
        int bitmask = prologue_regmask & 0xff;
        if (prologue_regmask & (1 << 14)) /* lr */
            bitmask |= 0x100;
        prologue[pos++] = 0xec | (bitmask >> 8); /* push {r0-r7,lr} */
        prologue[pos++] = bitmask & 0xff;
    }

    if (func->H)
        prologue[pos++] = 0x04; /* push {r0-r3} - handled as sub sp, sp, #16 */

    prologue[pos++] = 0xff; /* end */
    prologue_end = &prologue[pos];

    /* Synthesize epilogue opcodes */
    pos = 0;
    if (stack && !ef)
    {
        if (stack <= 0x7f)
        {
            epilogue[pos++] = stack; /* sub sp, sp, #x */
        }
        else
        {
            epilogue[pos++] = 0xe8 | (stack >> 8); /* sub.w sp, sp, #x */
            epilogue[pos++] = stack & 0xff;
        }
    }

    if (func->R && func->Reg != 7)
        epilogue[pos++] = 0xe0 | func->Reg; /* vpush {d8-dX} */

    if (epilogue_regmask & 0x7f00) /* r8-r11, lr set */
    {
        int bitmask = epilogue_regmask & 0x1fff;
        if (epilogue_regmask & (3 << 14)) /* lr or pc */
            bitmask |= 0x2000;
        epilogue[pos++] = 0x80 | (bitmask >> 8); /* push.w {r0-r12,lr} */
        epilogue[pos++] = bitmask & 0xff;
    }
    else if (epilogue_regmask) /* r0-r7, pc set */
    {
        int bitmask = epilogue_regmask & 0xff;
        if (epilogue_regmask & (1 << 15)) /* pc */
            bitmask |= 0x100; /* lr */
        epilogue[pos++] = 0xec | (bitmask >> 8); /* push {r0-r7,lr} */
        epilogue[pos++] = bitmask & 0xff;
    }

    if (func->H && !(func->L && func->Ret == 0))
        epilogue[pos++] = 0x04; /* add sp, sp, #16 */
    else if (func->H && (func->L && func->Ret == 0))
    {
        epilogue[pos++] = 0xef; /* ldr lr, [sp], #20 */
        epilogue[pos++] = 5;
    }

    if (func->Ret == 1)
        epilogue[pos++] = 0xfd; /* bx lr */
    else if (func->Ret == 2)
        epilogue[pos++] = 0xfe; /* b address */
    else
        epilogue[pos++] = 0xff; /* end */
    epilogue_end = &epilogue[pos];

    if (func->Flag == 1 && offset < 4 * (prologue_end - prologue)) {
        /* Check prologue */
        len = get_sequence_len( prologue, prologue_end, 0 );
        if (offset < len)
        {
            process_unwind_codes( prologue, prologue_end, context, ptrs, len - offset );
            return NULL;
        }
    }

    if (func->Ret != 3 && 2 * func->FunctionLength - offset <= 4 * (epilogue_end - epilogue)) {
        /* Check epilogue */
        len = get_sequence_len( epilogue, epilogue_end, 1 );
        if (offset >= 2 * func->FunctionLength - len)
        {
            process_unwind_codes( epilogue, epilogue_end, context, ptrs, offset - (2 * func->FunctionLength - len) );
            return NULL;
        }
    }

    /* Execute full prologue */
    process_unwind_codes( prologue, prologue_end, context, ptrs, 0 );

    return NULL;
}


/***********************************************************************
 *           unwind_full_data
 */
static void *unwind_full_data( ULONG_PTR base, ULONG_PTR pc, RUNTIME_FUNCTION *func,
                               CONTEXT *context, PVOID *handler_data, KNONVOLATILE_CONTEXT_POINTERS *ptrs )
{
    struct unwind_info *info;
    struct unwind_info_epilog *info_epilog;
    unsigned int i, codes, epilogs, len, offset;
    void *data;
    BYTE *end;

    info = (struct unwind_info *)((char *)base + func->UnwindData);
    data = info + 1;
    epilogs = info->epilog;
    codes = info->codes;
    if (!codes && !epilogs)
    {
        struct unwind_info_ext *infoex = data;
        codes = infoex->codes;
        epilogs = infoex->epilog;
        data = infoex + 1;
    }
    info_epilog = data;
    if (!info->e) data = info_epilog + epilogs;

    offset = (pc - base) - func->BeginAddress;
    end = (BYTE *)data + codes * 4;

    TRACE( "function %lx-%lx: len=%#x ver=%u X=%u E=%u F=%u epilogs=%u codes=%u\n",
           base + func->BeginAddress, base + func->BeginAddress + info->function_length * 2,
           info->function_length, info->version, info->x, info->e, info->f, epilogs, codes * 4 );

    /* check for prolog */
    if (offset < codes * 4 * 4 && !info->f)
    {
        len = get_sequence_len( data, end, 0 );
        if (offset < len)
        {
            process_unwind_codes( data, end, context, ptrs, len - offset );
            return NULL;
        }
    }

    /* check for epilog */
    if (!info->e)
    {
        for (i = 0; i < epilogs; i++)
        {
            /* TODO: Currently not checking epilogue conditions. */
            if (offset < 2 * info_epilog[i].offset) break;
            if (offset - 2 * info_epilog[i].offset < (codes * 4 - info_epilog[i].index) * 4)
            {
                BYTE *ptr = (BYTE *)data + info_epilog[i].index;
                len = get_sequence_len( ptr, end, 1 );
                if (offset <= 2 * info_epilog[i].offset + len)
                {
                    process_unwind_codes( ptr, end, context, ptrs, offset - 2 * info_epilog[i].offset );
                    return NULL;
                }
            }
        }
    }
    else if (2 * info->function_length - offset <= (codes * 4 - epilogs) * 4)
    {
        BYTE *ptr = (BYTE *)data + epilogs;
        len = get_sequence_len( ptr, end, 1 );
        if (offset >= 2 * info->function_length - len)
        {
            process_unwind_codes( ptr, end, context, ptrs, offset - (2 * info->function_length - len) );
            return NULL;
        }
    }

    process_unwind_codes( data, end, context, ptrs, 0 );

    /* get handler since we are inside the main code */
    if (info->x)
    {
        DWORD *handler_rva = (DWORD *)data + codes;
        *handler_data = handler_rva + 1;
        return (char *)base + *handler_rva;
    }
    return NULL;
}

/***********************************************************************
 *            RtlVirtualUnwind  (NTDLL.@)
 */
PVOID WINAPI RtlVirtualUnwind( ULONG type, ULONG_PTR base, ULONG_PTR pc,
                               RUNTIME_FUNCTION *func, CONTEXT *context,
                               PVOID *handler_data, ULONG_PTR *frame_ret,
                               KNONVOLATILE_CONTEXT_POINTERS *ctx_ptr )
{
    void *handler;

    TRACE( "type %lx pc %Ix sp %lx func %lx\n", type, pc, context->Sp, base + func->BeginAddress );

    *handler_data = NULL;

    context->Pc = 0;
    if (func->Flag)
        handler = unwind_packed_data( base, pc, func, context, ctx_ptr );
    else
        handler = unwind_full_data( base, pc, func, context, handler_data, ctx_ptr );

    TRACE( "ret: lr=%lx sp=%lx handler=%p\n", context->Lr, context->Sp, handler );
    if (!context->Pc)
        context->Pc = context->Lr;
    context->ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
    *frame_ret = context->Sp;
    return handler;
}


/**********************************************************************
 *           call_consolidate_callback
 *
 * Wrapper function to call a consolidate callback from a fake frame.
 * If the callback executes RtlUnwindEx (like for example done in C++ handlers),
 * we have to skip all frames which were already processed. To do that we
 * trick the unwinding functions into thinking the call came from somewhere
 * else. All CFI instructions are either DW_CFA_def_cfa_expression or
 * DW_CFA_expression, and the expressions have the following format:
 *
 * DW_OP_breg13; sleb128 <OFFSET>       | Load SP + struct member offset
 * [DW_OP_deref]                        | Dereference, only for CFA
 */
__ASM_GLOBAL_FUNC( call_consolidate_callback,
                   "push {r0-r2,lr}\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "sub sp, sp, #0x1a0\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "mov r1, r0\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "mov r0, sp\n\t"
                   __ASM_SEH(".seh_nop\n\t")
                   "mov r2, #0x1a0\n\t"
                   __ASM_SEH(".seh_nop_w\n\t")
                   "bl " __ASM_NAME("memcpy") "\n\t"
                   __ASM_SEH(".seh_custom 0xee,0x02\n\t")  /* MSFT_OP_CONTEXT */
                   __ASM_SEH(".seh_endprologue\n\t")
                   __ASM_CFI(".cfi_def_cfa 13, 0\n\t")
                   __ASM_CFI(".cfi_escape 0x0f,0x04,0x7d,0xb8,0x00,0x06\n\t") /* DW_CFA_def_cfa_expression: DW_OP_breg13 + 56, DW_OP_deref */
                   __ASM_CFI(".cfi_escape 0x10,0x04,0x02,0x7d,0x14\n\t") /* DW_CFA_expression: R4 DW_OP_breg13 + 20 */
                   __ASM_CFI(".cfi_escape 0x10,0x05,0x02,0x7d,0x18\n\t") /* DW_CFA_expression: R5 DW_OP_breg13 + 24 */
                   __ASM_CFI(".cfi_escape 0x10,0x06,0x02,0x7d,0x1c\n\t") /* DW_CFA_expression: R6 DW_OP_breg13 + 28 */
                   __ASM_CFI(".cfi_escape 0x10,0x07,0x02,0x7d,0x20\n\t") /* DW_CFA_expression: R7 DW_OP_breg13 + 32 */
                   __ASM_CFI(".cfi_escape 0x10,0x08,0x02,0x7d,0x24\n\t") /* DW_CFA_expression: R8 DW_OP_breg13 + 36 */
                   __ASM_CFI(".cfi_escape 0x10,0x09,0x02,0x7d,0x28\n\t") /* DW_CFA_expression: R9 DW_OP_breg13 + 40 */
                   __ASM_CFI(".cfi_escape 0x10,0x0a,0x02,0x7d,0x2c\n\t") /* DW_CFA_expression: R10 DW_OP_breg13 + 44 */
                   __ASM_CFI(".cfi_escape 0x10,0x0b,0x02,0x7d,0x30\n\t") /* DW_CFA_expression: R11 DW_OP_breg13 + 48 */
                   __ASM_CFI(".cfi_escape 0x10,0x0e,0x03,0x7d,0xc0,0x00\n\t") /* DW_CFA_expression: LR DW_OP_breg13 + 64 (PC) */
                   /* Libunwind doesn't support the registers D8-D15 like this */
#if 0
                   __ASM_CFI(".cfi_escape 0x10,0x88,0x02,0x03,0x7d,0x90,0x01\n\t") /* DW_CFA_expression: D8 DW_OP_breg13 + 144 */
                   __ASM_CFI(".cfi_escape 0x10,0x89,0x02,0x03,0x7d,0x98,0x01\n\t") /* DW_CFA_expression: D9 DW_OP_breg13 + 152 */
                   __ASM_CFI(".cfi_escape 0x10,0x8a,0x02,0x03,0x7d,0xa0,0x01\n\t") /* DW_CFA_expression: D10 DW_OP_breg13 + 160 */
                   __ASM_CFI(".cfi_escape 0x10,0x8b,0x02,0x03,0x7d,0xa8,0x01\n\t") /* DW_CFA_expression: D11 DW_OP_breg13 + 168 */
                   __ASM_CFI(".cfi_escape 0x10,0x8c,0x02,0x03,0x7d,0xb0,0x01\n\t") /* DW_CFA_expression: D12 DW_OP_breg13 + 176 */
                   __ASM_CFI(".cfi_escape 0x10,0x8d,0x02,0x03,0x7d,0xb8,0x01\n\t") /* DW_CFA_expression: D13 DW_OP_breg13 + 184 */
                   __ASM_CFI(".cfi_escape 0x10,0x8e,0x02,0x03,0x7d,0xc0,0x01\n\t") /* DW_CFA_expression: D14 DW_OP_breg13 + 192 */
                   __ASM_CFI(".cfi_escape 0x10,0x8f,0x02,0x03,0x7d,0xc8,0x01\n\t") /* DW_CFA_expression: D15 DW_OP_breg13 + 200 */
#endif
                   /* These EHABI opcodes are to be read bottom up - they
                    * restore relevant registers from the CONTEXT. */
                   __ASM_EHABI(".save {sp}\n\t") /* Restore Sp last */
                   __ASM_EHABI(".pad #-(0x80 + 0x0c + 0x0c)\n\t") /* Move back across D0-D15, Cpsr, Fpscr, Padding, Pc, Lr and Sp */
                   __ASM_EHABI(".vsave {d8-d15}\n\t")
                   __ASM_EHABI(".pad #0x40\n\t") /* Skip past D0-D7 */
                   __ASM_EHABI(".pad #0x0c\n\t") /* Skip past Cpsr, Fpscr and Padding */
                   __ASM_EHABI(".save {lr, pc}\n\t")
                   __ASM_EHABI(".pad #0x08\n\t") /* Skip past R12 and Sp - Sp is restored last */
                   __ASM_EHABI(".save {r4-r11}\n\t")
                   __ASM_EHABI(".pad #0x14\n\t") /* Skip past ContextFlags and R0-R3 */

                   "ldrd r1, r2, [sp, #0x1a4]\n\t"
                   "mov r0, r2\n\t"
                   "blx r1\n\t"
                   "add sp, sp, #0x1ac\n\t"
                   "pop {pc}\n\t")

void context_restore_from_jmpbuf( CONTEXT *context, void *buf )
{
    struct MSVCRT_JUMP_BUFFER *jmp = (struct MSVCRT_JUMP_BUFFER *)buf;
    int i;

    for (i = 4; i <= 11; i++)
        (&context->R4)[i-4] = (&jmp->R4)[i-4];
    context->Lr      = jmp->Pc;
    context->Sp      = jmp->Sp;
    context->Fpscr   = jmp->Fpscr;

    for (i = 0; i < 8; i++)
        context->D[8+i] = jmp->D[i];
}

void context_trace_gprs( CONTEXT *context )
{
    TRACE("  r0=%08lx  r1=%08lx  r2=%08lx  r3=%08lx\n",
          context->R0, context->R1, context->R2, context->R3 );
    TRACE("  r4=%08lx  r5=%08lx  r6=%08lx  r7=%08lx\n",
          context->R4, context->R5, context->R6, context->R7 );
    TRACE("  r8=%08lx  r9=%08lx r10=%08lx r11=%08lx\n",
          context->R8, context->R9, context->R10, context->R11 );
    TRACE(" r12=%08lx  sp=%08lx  lr=%08lx  pc=%08lx\n",
          context->R12, context->Sp, context->Lr, context->Pc );
}

__ASM_GLOBAL_FUNC( __C_ExecuteExceptionFilter,
                   "push {r4-r11,lr}\n\t"
                   __ASM_EHABI(".save {r4-r11,lr}\n\t")
                   __ASM_SEH(".seh_save_regs_w {r4-r11,lr}\n\t")
                   __ASM_SEH(".seh_endprologue\n\t")

                   __ASM_CFI(".cfi_def_cfa 13, 36\n\t")
                   __ASM_CFI(".cfi_offset r4, -36\n\t")
                   __ASM_CFI(".cfi_offset r5, -32\n\t")
                   __ASM_CFI(".cfi_offset r6, -28\n\t")
                   __ASM_CFI(".cfi_offset r7, -24\n\t")
                   __ASM_CFI(".cfi_offset r8, -20\n\t")
                   __ASM_CFI(".cfi_offset r9, -16\n\t")
                   __ASM_CFI(".cfi_offset r10, -12\n\t")
                   __ASM_CFI(".cfi_offset r11, -8\n\t")
                   __ASM_CFI(".cfi_offset lr, -4\n\t")

                   "ldm r3, {r4-r11,lr}\n\t"
                   "blx r2\n\t"
                   "pop {r4-r11,pc}\n\t" )

/* This is, implementation wise, identical to __C_ExecuteExceptionFilter. */
__ASM_GLOBAL_FUNC( __C_ExecuteTerminationHandler,
                   "b " __ASM_NAME("__C_ExecuteExceptionFilter") "\n\t");

/***********************************************************************
 *		RtlRaiseException (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( RtlRaiseException,
                    "push {r0, lr}\n\t"
                    __ASM_EHABI(".save {r0, lr}\n\t")
                    __ASM_SEH(".seh_save_regs {r0, lr}\n\t")
                    "sub sp, sp, #0x1a0\n\t"  /* sizeof(CONTEXT) */
                    __ASM_EHABI(".pad #0x1a0\n\t")
                    __ASM_SEH(".seh_stackalloc 0x1a0\n\t")
                    __ASM_SEH(".seh_endprologue\n\t")
                    __ASM_CFI(".cfi_adjust_cfa_offset 424\n\t")
                    __ASM_CFI(".cfi_offset lr, -4\n\t")
                    "mov r0, sp\n\t"  /* context */
                    "bl " __ASM_NAME("RtlCaptureContext") "\n\t"
                    "ldr r0, [sp, #0x1a0]\n\t" /* rec */
                    "ldr r1, [sp, #0x1a4]\n\t"
                    "str r1, [sp, #0x3c]\n\t"  /* context->Lr */
                    "str r1, [sp, #0x40]\n\t"  /* context->Pc */
                    "mrs r2, CPSR\n\t"
                    "bfi r2, r1, #5, #1\n\t"   /* Thumb bit */
                    "str r2, [sp, #0x44]\n\t"  /* context->Cpsr */
                    "str r1, [r0, #12]\n\t"    /* rec->ExceptionAddress */
                    "add r1, sp, #0x1a8\n\t"
                    "str r1, [sp, #0x38]\n\t"  /* context->Sp */
                    "mov r1, sp\n\t"
                    "mrc p15, 0, r3, c13, c0, 2\n\t" /* NtCurrentTeb() */
                    "ldr r3, [r3, #0x30]\n\t"  /* peb */
                    "ldrb r2, [r3, #2]\n\t"    /* peb->BeingDebugged */
                    "cbnz r2, 1f\n\t"
                    "bl " __ASM_NAME("dispatch_exception") "\n"
                    "1:\tmov r2, #1\n\t"
                    "bl " __ASM_NAME("NtRaiseException") "\n\t"
                    "bl " __ASM_NAME("RtlRaiseStatus") )

/***********************************************************************
 *           RtlUserThreadStart (NTDLL.@)
 */
#ifdef __WINE_PE_BUILD
__ASM_GLOBAL_FUNC( RtlUserThreadStart,
                   ".seh_endprologue\n\t"
                   "mov r2, r1\n\t"
                   "mov r1, r0\n\t"
                   "mov r0, #0\n\t"
                   "ldr ip, 1f\n\t"
                   "ldr ip, [ip]\n\t"
                   "blx ip\n"
                   "1:\t.long " __ASM_NAME("pBaseThreadInitThunk") "\n\t"
                   ".seh_handler " __ASM_NAME("call_unhandled_exception_handler") ", %except" )
#else
void WINAPI RtlUserThreadStart( PRTL_THREAD_START_ROUTINE entry, void *arg )
{
    __TRY
    {
        pBaseThreadInitThunk( 0, (LPTHREAD_START_ROUTINE)entry, arg );
    }
    __EXCEPT(call_unhandled_exception_filter)
    {
        NtTerminateProcess( GetCurrentProcess(), GetExceptionCode() );
    }
    __ENDTRY
}
#endif

/******************************************************************
 *		LdrInitializeThunk (NTDLL.@)
 */
void WINAPI LdrInitializeThunk( CONTEXT *context, ULONG_PTR unk2, ULONG_PTR unk3, ULONG_PTR unk4 )
{
    loader_init( context, (void **)&context->R0 );
    TRACE_(relay)( "\1Starting thread proc %p (arg=%p)\n", (void *)context->R0, (void *)context->R1 );
    NtContinue( context, TRUE );
}

/**********************************************************************
 *              DbgBreakPoint   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgBreakPoint, "udf #0xfe; bx lr; nop; nop; nop; nop" );

/**********************************************************************
 *              DbgUserBreakPoint   (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( DbgUserBreakPoint, "udf #0xfe; bx lr; nop; nop; nop; nop" );

#endif  /* __arm__ */
