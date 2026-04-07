#pragma once
#include <ntddk.h>

// ==============================================================================
// AMD SVM (Secure Virtual Machine) - DR Hooking Skeleton
// This file is strictly for AMD-V architecture reference and does not
// interfere with the Intel VT-x implementation.
// ==============================================================================

// SVM Exit Codes (Intercepts)
#define SVM_EXIT_READ_DR0       0x0020
#define SVM_EXIT_READ_DR1       0x0021
#define SVM_EXIT_READ_DR2       0x0022
#define SVM_EXIT_READ_DR3       0x0023
#define SVM_EXIT_READ_DR4       0x0024
#define SVM_EXIT_READ_DR5       0x0025
#define SVM_EXIT_READ_DR6       0x0026
#define SVM_EXIT_READ_DR7       0x0027
#define SVM_EXIT_WRITE_DR0      0x0030
#define SVM_EXIT_WRITE_DR1      0x0031
#define SVM_EXIT_WRITE_DR2      0x0032
#define SVM_EXIT_WRITE_DR3      0x0033
#define SVM_EXIT_WRITE_DR4      0x0034
#define SVM_EXIT_WRITE_DR5      0x0035
#define SVM_EXIT_WRITE_DR6      0x0036
#define SVM_EXIT_WRITE_DR7      0x0037

#define SVM_EXIT_EXCP_BASE      0x0040
#define SVM_EXIT_EXCP_DB        (SVM_EXIT_EXCP_BASE + 1) // #DB Exception
#define SVM_EXIT_EXCP_BP        (SVM_EXIT_EXCP_BASE + 3) // #BP Exception

#define SVM_EXIT_VMMCALL        0x0081

// ------------------------------------------------------------------------------
// VMCB Control Area (1024 Bytes)
// AMD Manual Vol 2 - Appendix B.1
// ------------------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _VMCB_CONTROL_AREA
{
    ULONG32 InterceptCr;        // 000h
    ULONG32 InterceptDr;        // 004h - Bit 0=ReadDR0 ... Bit 16=WriteDR0
    ULONG32 InterceptException; // 008h - Bit 1=#DB
    ULONG32 InterceptMisc1;     // 00Ch
    ULONG32 InterceptMisc2;     // 010h
    ULONG32 InterceptMisc3;     // 014h
    // ... padding for brevity ...
    UCHAR   Reserved1[0x28];    // 018h
    USHORT  PauseFilterThreshold;// 040h
    USHORT  PauseFilterCount;   // 042h
    ULONG64 IopmBasePa;         // 048h
    ULONG64 MsrpmBasePa;        // 050h
    ULONG64 TscOffset;          // 058h
    ULONG32 GuestAsid;          // 060h
    // ... padding for brevity ...
    UCHAR   Reserved2[0x0C];    // 064h
    ULONG64 ExitCode;           // 070h - The reason for VMEXIT
    ULONG64 ExitInfo1;          // 078h
    ULONG64 ExitInfo2;          // 080h
    ULONG32 ExitIntInfo;        // 088h
    ULONG32 NpEnable;           // 08Ch - Nested Paging
    // ... padding up to 0x400 ...
    UCHAR   Reserved3[0x370];   // 090h
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;

// ------------------------------------------------------------------------------
// VMCB State Save Area (3072 Bytes)
// AMD Manual Vol 2 - Appendix B.2
// Note: AMD allows direct reading/writing of Guest State from memory!
// ------------------------------------------------------------------------------
typedef struct _VMCB_STATE_SAVE_AREA
{
    // Segment registers (ES, CS, SS, DS, FS, GS, GDTR, LDTR, IDTR, TR)
    UCHAR   Reserved1[0x0CB];   // 000h
    ULONG64 Cpl;                // 0CBh
    ULONG32 Efer;               // 0D0h
    // ... padding ...
    UCHAR   Reserved2[0x06C];   // 0D8h
    ULONG64 Cr4;                // 148h
    ULONG64 Cr3;                // 150h
    ULONG64 Cr0;                // 158h
    ULONG64 Dr7;                // 160h
    ULONG64 Dr6;                // 168h
    ULONG64 Rflags;             // 170h
    ULONG64 Rip;                // 178h
    // ... padding ...
    UCHAR   Reserved3[0x058];   // 180h
    ULONG64 Rsp;                // 1D8h
    ULONG64 Rax;                // 1E0h
    ULONG64 Star;               // 1E8h
    ULONG64 Lstar;              // 1F0h
    // ... padding up to 0xC00 ...
    UCHAR   Reserved4[0xA08];   // 1F8h
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;

// ------------------------------------------------------------------------------
// Complete VMCB
// ------------------------------------------------------------------------------
typedef struct _VMCB
{
    VMCB_CONTROL_AREA       ControlArea;
    VMCB_STATE_SAVE_AREA    StateSaveArea;
} VMCB, *PVMCB;
#pragma pack(pop)

// ------------------------------------------------------------------------------
// Common Guest Context (Registers not in VMCB are saved manually via PUSHA)
// ------------------------------------------------------------------------------
typedef struct _GUEST_CONTEXT_SVM
{
    ULONG64 R15;
    ULONG64 R14;
    ULONG64 R13;
    ULONG64 R12;
    ULONG64 R11;
    ULONG64 R10;
    ULONG64 R9;
    ULONG64 R8;
    ULONG64 Rdi;
    ULONG64 Rsi;
    ULONG64 Rbp;
    ULONG64 Rsp;
    ULONG64 Rbx;
    ULONG64 Rdx;
    ULONG64 Rcx;
    ULONG64 Rax;
} GUEST_CONTEXT_SVM, *PGUEST_CONTEXT_SVM;

// ------------------------------------------------------------------------------
// Prototypes for AMD SVM Exit Handlers
// ------------------------------------------------------------------------------
BOOLEAN SvmHandleDebugException(PVMCB Vmcb, PGUEST_CONTEXT_SVM Context);
BOOLEAN SvmHandleDrAccess(PVMCB Vmcb, PGUEST_CONTEXT_SVM Context);
