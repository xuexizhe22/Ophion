#include "svm.h"

// ==============================================================================
// AMD SVM (Secure Virtual Machine) - DR Hooking Exit Handlers
// This file is strictly for AMD-V architecture reference and does not
// interfere with the Intel VT-x implementation.
// ==============================================================================

// Global fake debug registers to hide our hooks from the guest
static ULONG64 g_FakeDr0 = 0;
static ULONG64 g_FakeDr1 = 0;
static ULONG64 g_FakeDr2 = 0;
static ULONG64 g_FakeDr3 = 0;
static ULONG64 g_FakeDr6 = 0xFFFF0FF0; // Default power-on state
static ULONG64 g_FakeDr7 = 0x00000400; // Default power-on state

// ------------------------------------------------------------------------------
// SvmHandleDebugException
// Handles #DB (SVM_EXIT_EXCP_BASE + 1).
// This is triggered when a hardware breakpoint is hit.
// AMD VMCB makes this incredibly easy: just read Vmcb->StateSaveArea.Rip!
// ------------------------------------------------------------------------------
BOOLEAN SvmHandleDebugException(PVMCB Vmcb, PGUEST_CONTEXT_SVM Context)
{
    // Read the current Guest RIP directly from VMCB Memory!
    // No VMREAD needed!
    ULONG64 GuestRip = Vmcb->StateSaveArea.Rip;

    // DR6 ExitInfo1 contains the DR6 value that would have been generated
    ULONG64 Dr6_Info = Vmcb->ControlArea.ExitInfo1;

    // Check if DR0 triggered the #DB (Bit 0 of DR6)
    if (Dr6_Info & 0x1)
    {
        DbgPrint("[AMD-SVM] #DB intercepted at RIP: %llx (DR0 matched)\n", GuestRip);

        // ==========================================
        // HOOK ACTION HERE
        // ==========================================
        // 1. You can modify context registers directly (e.g., Context->Rax = 1;)
        // 2. You can redirect RIP by modifying Vmcb->StateSaveArea.Rip
        // 3. You must clear the Resume Flag (RF) if stepping, or handle EFLAGS.

        // Clear the DR0 hit flag in guest DR6 to hide it
        Vmcb->StateSaveArea.Dr6 &= ~0x1ULL;
    }

    // After handling the #DB, we inject the #DB back to the guest ONLY IF
    // it was not our hidden hook. If it was our hook, we just resume guest execution.

    // For demonstration, we simply resume:
    return TRUE; // TRUE means "handled, do not inject into guest"
}

// ------------------------------------------------------------------------------
// SvmHandleDrAccess
// Handles SVM_EXIT_READ_DRx and SVM_EXIT_WRITE_DRx
// Intercepts anti-cheat attempts to read/write DR registers.
// ------------------------------------------------------------------------------
BOOLEAN SvmHandleDrAccess(PVMCB Vmcb, PGUEST_CONTEXT_SVM Context)
{
    ULONG64 ExitCode = Vmcb->ControlArea.ExitCode;

    // AMD stores the GPR number used in the MOV DR instruction in ExitInfo1
    // e.g., if ExitInfo1 == 0, the register is RAX.
    ULONG64 GprIndex = Vmcb->ControlArea.ExitInfo1;

    // A helper macro to get/set GPR based on ExitInfo1 index (0-15)
    // In AMD, standard ordering: 0=RAX, 1=RCX, 2=RDX, 3=RBX, 4=RSP, 5=RBP, 6=RSI, 7=RDI, 8-15=R8-R15
    PULONG64 GprPtr = NULL;
    switch (GprIndex)
    {
        case 0: GprPtr = &Context->Rax; break;
        case 1: GprPtr = &Context->Rcx; break;
        case 2: GprPtr = &Context->Rdx; break;
        case 3: GprPtr = &Context->Rbx; break;
        case 4: GprPtr = &Vmcb->StateSaveArea.Rsp; break; // RSP is in VMCB!
        case 5: GprPtr = &Context->Rbp; break;
        case 6: GprPtr = &Context->Rsi; break;
        case 7: GprPtr = &Context->Rdi; break;
        case 8: GprPtr = &Context->R8; break;
        case 9: GprPtr = &Context->R9; break;
        case 10: GprPtr = &Context->R10; break;
        case 11: GprPtr = &Context->R11; break;
        case 12: GprPtr = &Context->R12; break;
        case 13: GprPtr = &Context->R13; break;
        case 14: GprPtr = &Context->R14; break;
        case 15: GprPtr = &Context->R15; break;
        default: return FALSE; // Invalid GPR
    }

    // Handle READ from DR
    if (ExitCode >= SVM_EXIT_READ_DR0 && ExitCode <= SVM_EXIT_READ_DR7)
    {
        switch (ExitCode)
        {
            case SVM_EXIT_READ_DR0: *GprPtr = g_FakeDr0; break;
            case SVM_EXIT_READ_DR1: *GprPtr = g_FakeDr1; break;
            case SVM_EXIT_READ_DR2: *GprPtr = g_FakeDr2; break;
            case SVM_EXIT_READ_DR3: *GprPtr = g_FakeDr3; break;
            case SVM_EXIT_READ_DR6: *GprPtr = g_FakeDr6; break;
            case SVM_EXIT_READ_DR7: *GprPtr = g_FakeDr7; break;
        }
    }
    // Handle WRITE to DR
    else if (ExitCode >= SVM_EXIT_WRITE_DR0 && ExitCode <= SVM_EXIT_WRITE_DR7)
    {
        switch (ExitCode)
        {
            case SVM_EXIT_WRITE_DR0: g_FakeDr0 = *GprPtr; break;
            case SVM_EXIT_WRITE_DR1: g_FakeDr1 = *GprPtr; break;
            case SVM_EXIT_WRITE_DR2: g_FakeDr2 = *GprPtr; break;
            case SVM_EXIT_WRITE_DR3: g_FakeDr3 = *GprPtr; break;
            case SVM_EXIT_WRITE_DR6: g_FakeDr6 = *GprPtr; break;
            case SVM_EXIT_WRITE_DR7: g_FakeDr7 = *GprPtr; break;
        }
    }

    // Skip the instruction:
    // In AMD SVM, Vmcb->ControlArea.ExitInfo2 for DR accesses contains the next RIP!
    // This avoids having to decode the instruction length manually.
    Vmcb->StateSaveArea.Rip = Vmcb->ControlArea.ExitInfo2;

    return TRUE;
}
