/*
*   vmexit.c - vm-exit handler — dispatches exits to sub-handlers
*   this is called from assembly (asm_vmexit_handler) with:
*   rcx = pguest_regs (pushed gprs on stack)
*/
#include "hv.h"
#include <Zydis/Zydis.h>

static volatile LONG g_synthetic_msr_log_budget = 8;
static volatile LONG g_guest_idle_log_budget = 1;
static volatile LONG g_crash_msr_log_budget = 4;
static volatile LONG64 g_hv_crash_msrs[6] = {0};

#define HV_RFLAGS_CF               0x00000001ULL
#define HV_RFLAGS_PF               0x00000004ULL
#define HV_RFLAGS_AF               0x00000010ULL
#define HV_RFLAGS_ZF               0x00000040ULL
#define HV_RFLAGS_SF               0x00000080ULL
#define HV_RFLAGS_OF               0x00000800ULL

#define HV_CR0_PG_FLAG             (1ULL << 31)
#define HV_GUEST_PTE_PRESENT       (1ULL << 0)
#define HV_GUEST_PTE_LARGE_PAGE    (1ULL << 7)
#define HV_GUEST_PTE_PFN_MASK      0x000FFFFFFFFFF000ULL

#ifndef HV_X64_MSR_GUEST_IDLE
#define HV_X64_MSR_GUEST_IDLE 0x400000F0U
#endif

#ifndef HV_X64_MSR_CRASH_P0
#define HV_X64_MSR_CRASH_P0   0x40000100U
#define HV_X64_MSR_CRASH_P1   0x40000101U
#define HV_X64_MSR_CRASH_P2   0x40000102U
#define HV_X64_MSR_CRASH_P3   0x40000103U
#define HV_X64_MSR_CRASH_P4   0x40000104U
#define HV_X64_MSR_CRASH_CTL  0x40000105U
#endif

static __forceinline VOID
vmexit_advance_rip(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 instr_len = 0;
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);

    UINT64 new_rip = vcpu->vmexit_rip + instr_len;
    __vmx_vmwrite(VMCS_GUEST_RIP, new_rip);

    //
    // merge hardware breakpoint matches into pending debug exceptions.
    // on bare metal, when TF is set and a hardware BP matches the next
    // instruction, the CPU delivers #DB with DR6 = BS | Bn | ENABLED_BP.
    // after a VM-exit (eg. CPUID), the CPU saves the BS bit in the
    // pending debug field but does NOT check DR0-DR3 — we must do that.
    //
    UINT64 pending = 0;
    __vmx_vmread(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, &pending);

    if (pending == 0)
        return;  // fast path: no single-step or debug activity

    //
    // read guest DR7 from VMCS (not __readdr(7) which returns host value)
    //
    UINT64 dr7 = 0;
    __vmx_vmread(VMCS_GUEST_DR7, &dr7);

    //
    // check each DR0-DR3: enabled (L or G bit) + execution breakpoint (R/W=00)
    //
    static const UINT64 ln_bits[] = { DR7_L0, DR7_L1, DR7_L2, DR7_L3 };
    static const UINT64 gn_bits[] = { DR7_G0, DR7_G1, DR7_G2, DR7_G3 };
    static const UINT64 bn_bits[] = { PENDING_DEBUG_B0, PENDING_DEBUG_B1,
                                      PENDING_DEBUG_B2, PENDING_DEBUG_B3 };

    UINT64 bp_matched = 0;

    for (int i = 0; i < 4; i++)
    {
        // skip if this breakpoint is not enabled (neither local nor global)
        if (!(dr7 & (ln_bits[i] | gn_bits[i])))
            continue;

        // skip if not an execution breakpoint (R/W must be 00)
        if ((dr7 & DR7_RW_MASK(i)) != 0)
            continue;

        UINT64 drn;
        switch (i)
        {
        case 0: drn = vcpu->guest_dr0; break;
        case 1: drn = vcpu->guest_dr1; break;
        case 2: drn = vcpu->guest_dr2; break;
        case 3: drn = vcpu->guest_dr3; break;
        default: continue;
        }

        if (drn == new_rip)
            bp_matched |= bn_bits[i];
    }

    if (bp_matched)
    {
        pending |= bp_matched | PENDING_DEBUG_ENABLED_BP;
        __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, pending);
    }
}

static __forceinline BOOLEAN
vmexit_try_read_msr(UINT32 target_msr, UINT64 *value, NTSTATUS *status)
{
    __try
    {
        *value = __readmsr(target_msr);
        if (status)
            *status = STATUS_SUCCESS;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (status)
            *status = GetExceptionCode();
        return FALSE;
    }
}

static __forceinline BOOLEAN
vmexit_try_write_msr(UINT32 target_msr, UINT64 value, NTSTATUS *status)
{
    __try
    {
        __writemsr(target_msr, value);
        if (status)
            *status = STATUS_SUCCESS;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (status)
            *status = GetExceptionCode();
        return FALSE;
    }
}

static __forceinline VOID
vmexit_log_synthetic_msr(BOOLEAN is_write, UINT32 target_msr, BOOLEAN passed_through, NTSTATUS status)
{
    LONG remaining = InterlockedDecrement(&g_synthetic_msr_log_budget);
    if (remaining < 0)
        return;

    DbgPrintEx(0, 0,
             "[hv] %s synthetic MSR 0x%08X -> %s (outer_hv=%d, status=0x%08X)\n",
             is_write ? "WRMSR" : "RDMSR",
             target_msr,
             passed_through ? "pass-through" : "#GP",
             g_stealth_cpuid_cache.outer_hypervisor_present,
             (UINT32)status);
}

static __forceinline VOID
vmexit_emulate_guest_idle(VIRTUAL_MACHINE_STATE *vcpu)
{
    //
    // HV_X64_MSR_GUEST_IDLE is a side-effecting RDMSR. Reading it from VMX
    // root would act on the outer hypervisor's VP, not just the nested guest.
    //
    // Entering VMCS guest HLT state looked architecturally closer, but under
    // VMware nested VT-x it can deadlock the nested guest very early in the
    // idle path. For stability, use a compatibility fallback: retire the
    // instruction successfully and return zero without descheduling the VP.
    //
    // This is not a faithful idle implementation, but it keeps the guest
    // moving while we stabilize nested-HV behavior.
    //
    vcpu->regs->rax = 0;
    vcpu->regs->rdx = 0;

    if (InterlockedDecrement(&g_guest_idle_log_budget) >= 0)
    {
        DbgPrintEx(0, 0, "[hv] RDMSR synthetic MSR 0x%08X -> guest idle compatibility return\n",
                 HV_X64_MSR_GUEST_IDLE);
    }
}

static __forceinline BOOLEAN
vmexit_is_crash_msr(UINT32 target_msr)
{
    return target_msr >= HV_X64_MSR_CRASH_P0 &&
           target_msr <= HV_X64_MSR_CRASH_CTL;
}

static __forceinline VOID
vmexit_handle_crash_msr_read(VIRTUAL_MACHINE_STATE *vcpu, UINT32 target_msr)
{
    UINT32 index = target_msr - HV_X64_MSR_CRASH_P0;
    UINT64 value = (UINT64)g_hv_crash_msrs[index];

    vcpu->regs->rax = (UINT64)(UINT32)value;
    vcpu->regs->rdx = value >> 32;
}

static __forceinline VOID
vmexit_handle_crash_msr_write(UINT32 target_msr, UINT64 value)
{
    UINT32 index = target_msr - HV_X64_MSR_CRASH_P0;
    InterlockedExchange64(&g_hv_crash_msrs[index], (LONG64)value);

    if (target_msr == HV_X64_MSR_CRASH_CTL &&
        InterlockedDecrement(&g_crash_msr_log_budget) >= 0)
    {
        DbgPrintEx(0, 0,
                 "[hv] Guest crash enlightenment intercepted: "
                 "P0=0x%llX P1=0x%llX P2=0x%llX P3=0x%llX P4=0x%llX CTL=0x%llX\n",
                 (UINT64)g_hv_crash_msrs[0],
                 (UINT64)g_hv_crash_msrs[1],
                 (UINT64)g_hv_crash_msrs[2],
                 (UINT64)g_hv_crash_msrs[3],
                 (UINT64)g_hv_crash_msrs[4],
                 (UINT64)g_hv_crash_msrs[5]);
    }
}

//
// exception classification for double-fault generation (SDM Vol 3 Table 6-5)
//
// contributory: #DE(0), #TS(10), #NP(11), #SS(12), #GP(13)
// page fault:   #PF(14)
// double fault: #DF(8)
// everything else: benign
//

typedef enum {
    EXCEPTION_CLASS_BENIGN,
    EXCEPTION_CLASS_CONTRIBUTORY,
    EXCEPTION_CLASS_PAGE_FAULT,
    EXCEPTION_CLASS_DOUBLE_FAULT
} EXCEPTION_CLASS;

static __forceinline EXCEPTION_CLASS
classify_exception(UINT32 vector)
{
    switch (vector)
    {
    case EXCEPTION_VECTOR_DIVIDE_ERROR:
    case EXCEPTION_VECTOR_INVALID_TSS:
    case EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT:
    case EXCEPTION_VECTOR_STACK_SEGMENT_FAULT:
    case EXCEPTION_VECTOR_GENERAL_PROTECTION:
        return EXCEPTION_CLASS_CONTRIBUTORY;
    case EXCEPTION_VECTOR_PAGE_FAULT:
        return EXCEPTION_CLASS_PAGE_FAULT;
    case EXCEPTION_VECTOR_DOUBLE_FAULT:
        return EXCEPTION_CLASS_DOUBLE_FAULT;
    default:
        return EXCEPTION_CLASS_BENIGN;
    }
}

static __forceinline BOOLEAN
should_generate_df(UINT32 first_vector, UINT32 second_vector)
{
    EXCEPTION_CLASS first  = classify_exception(first_vector);
    EXCEPTION_CLASS second = classify_exception(second_vector);

    // contributory + contributory = #DF
    if (first == EXCEPTION_CLASS_CONTRIBUTORY && second == EXCEPTION_CLASS_CONTRIBUTORY)
        return TRUE;

    // PF + contributory or PF + PF = #DF
    if (first == EXCEPTION_CLASS_PAGE_FAULT &&
        (second == EXCEPTION_CLASS_CONTRIBUTORY || second == EXCEPTION_CLASS_PAGE_FAULT))
        return TRUE;

    return FALSE;
}

UINT64
vmx_return_rsp_for_vmxoff(VOID)
{
    UINT32                  core_id = (UINT32)(__readmsr(IA32_TSC_AUX) & 0xFFF);
    VIRTUAL_MACHINE_STATE * vcpu   = &g_vcpu[core_id];
    return vcpu->vmxoff.guest_rsp;
}

UINT64
vmx_return_rip_for_vmxoff(VOID)
{
    UINT32                  core_id = (UINT32)(__readmsr(IA32_TSC_AUX) & 0xFFF);
    VIRTUAL_MACHINE_STATE * vcpu   = &g_vcpu[core_id];
    return vcpu->vmxoff.guest_rip;
}

//
// Defeats:
//   - compare CPUID(0x04201337) vs CPUID(0x40000000)
//   - CPUID(max_leaf) vs CPUID(0x40000000)
//   - CPUID.1.ECX[31] hypervisor present bit
//   - CPUID subleaf handling
//   - some more
//
// Strategy:
//   before VMXON, we cache what the real CPU returns for an out-of-range leaf.
//   during VM-exit, if the guest queries an invalid/hypervisor leaf, we return
//   the cached response — identical to what bare metal would return.
//   for leaf 1, we clear ECX[31] (hypervisor present bit).
//

VOID
vmexit_handle_cpuid(VIRTUAL_MACHINE_STATE * vcpu)
{
    INT32       cpu_info[4] = {0};
    PGUEST_REGS regs       = vcpu->regs;
    UINT32      leaf       = (UINT32)regs->rax;
    UINT32      subleaf    = (UINT32)regs->rcx;

#if STEALTH_CPUID_CACHING
    //
    // if stealth is enabled and this leaf is invalid/out-of-range,
    // return the cached bare-metal response for perfect consistency.
    // on real hardware, CPUID(0x40000000) == CPUID(0x04201337) == CPUID(max+1)
    //
    if (g_stealth_enabled && stealth_is_leaf_invalid(leaf))
    {
        cpu_info[0] = g_stealth_cpuid_cache.invalid_leaf[0];
        cpu_info[1] = g_stealth_cpuid_cache.invalid_leaf[1];
        cpu_info[2] = g_stealth_cpuid_cache.invalid_leaf[2];
        cpu_info[3] = g_stealth_cpuid_cache.invalid_leaf[3];
    }
    else
#endif
    {
        __cpuidex(cpu_info, (int)leaf, (int)subleaf);

        //
        // leaf 1: clear the hypervisor present bit (ECX[31])
        // this is the primary detection used by EAC, BattlEye, VMAware, etc.
        //
        if (leaf == 1 && g_stealth_enabled)
        {
            cpu_info[2] &= ~((1 << 31) | (1 << 6));
        }
    }

    regs->rax = (UINT64)cpu_info[0];
    regs->rbx = (UINT64)cpu_info[1];
    regs->rcx = (UINT64)cpu_info[2];
    regs->rdx = (UINT64)cpu_info[3];
}

//
// Defeats:
//   - MSRs 0x40000000+ must #GP like bare metal
//   - IA32_FEATURE_CONTROL must hide VMX/SMX enables
//

VOID
vmexit_handle_msr_read(VIRTUAL_MACHINE_STATE * vcpu)
{
    MSR         msr       = {0};
    PGUEST_REGS regs      = vcpu->regs;
    UINT32      target_msr = (UINT32)(regs->rcx & 0xFFFFFFFF);

    if (target_msr == HV_X64_MSR_GUEST_IDLE)
    {
        vmexit_emulate_guest_idle(vcpu);
        return;
    }

    if (vmexit_is_crash_msr(target_msr))
    {
        vmexit_handle_crash_msr_read(vcpu, target_msr);
        return;
    }

    //
    // hypervisor synthetic MSRs (0x40000000+) — inject #GP on bare metal
    // this includes Hyper-V (0x40000000-0x400000FF) and KVM (0x4b564d00-02) MSRs
    //
    if (target_msr >= 0x40000000 && target_msr <= 0x4FFFFFFF)
    {
        NTSTATUS status = STATUS_PRIVILEGED_INSTRUCTION;

        if (g_stealth_cpuid_cache.outer_hypervisor_present &&
            vmexit_try_read_msr(target_msr, &msr.Flags, &status))
        {
            vmexit_log_synthetic_msr(FALSE, target_msr, TRUE, status);
            regs->rax = (UINT64)msr.Fields.Low;
            regs->rdx = (UINT64)msr.Fields.High;
            return;
        }

        vmexit_log_synthetic_msr(FALSE, target_msr, FALSE, status);
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    //
    // only service MSRs in valid architectural ranges
    //
    if ((target_msr <= 0x00001FFF) ||
        ((0xC0000000 <= target_msr) && (target_msr <= 0xC0001FFF)))
    {
        switch (target_msr)
        {
        case IA32_SYSENTER_CS:
            __vmx_vmread(VMCS_GUEST_SYSENTER_CS, &msr.Flags);
            break;

        case IA32_SYSENTER_ESP:
            __vmx_vmread(VMCS_GUEST_SYSENTER_ESP, &msr.Flags);
            break;

        case IA32_SYSENTER_EIP:
            __vmx_vmread(VMCS_GUEST_SYSENTER_EIP, &msr.Flags);
            break;

        case IA32_GS_BASE:
            __vmx_vmread(VMCS_GUEST_GS_BASE, &msr.Flags);
            break;

        case IA32_FS_BASE:
            __vmx_vmread(VMCS_GUEST_FS_BASE, &msr.Flags);
            break;

        //
        // IA32_TIME_STAMP_COUNTER (MSR 0x10)
        //
        // intercepted via MSR bitmap. in the handler, __rdtsc() returns raw
        // hardware TSC (no offset in VMX root), so we apply TSC_OFFSET manually.
        // per SDM 27.6.5, "use TSC offsetting" applies the same offset to RDTSC,
        // RDTSCP, and RDMSR of this MSR — interception is only needed so the
        // TSC compensation path can also cover RDMSR-based timing attacks.
        //
        case 0x10:
        {
            if (g_stealth_enabled)
            {
                size_t tsc_offset_raw = 0;
                __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &tsc_offset_raw);
                msr.Flags = (UINT64)((INT64)__rdtsc() + (INT64)tsc_offset_raw);
            }
            else
            {
                msr.Flags = __rdtsc();
            }
            break;
        }

        case IA32_FEATURE_CONTROL:
        {
            IA32_FEATURE_CONTROL_REGISTER feat = {0};
            feat.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

            if (g_stealth_enabled)
            {
                feat.Lock                      = 1;
                feat.EnableVmxInsideSmx        = 0;
                feat.EnableVmxOutsideSmx       = 0;
                feat.SenterLocalFunctionEnables = 0;
                feat.SenterGlobalEnable        = 0;
                feat.SgxLaunchControlEnable    = 0;
                feat.SgxGlobalEnable           = 0;
            }

            msr.Flags = feat.AsUInt;
            break;
        }

        default:
            msr.Flags = __readmsr(target_msr);
            break;
        }

        regs->rax = (UINT64)msr.Fields.Low;
        regs->rdx = (UINT64)msr.Fields.High;
    }
    else
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }
}

VOID
vmexit_handle_msr_write(VIRTUAL_MACHINE_STATE * vcpu)
{
    MSR         msr       = {0};
    PGUEST_REGS regs      = vcpu->regs;
    UINT32      target_msr = (UINT32)(regs->rcx & 0xFFFFFFFF);

    msr.Fields.Low  = (ULONG)regs->rax;
    msr.Fields.High = (ULONG)regs->rdx;

    if (vmexit_is_crash_msr(target_msr))
    {
        vmexit_handle_crash_msr_write(target_msr, msr.Flags);
        return;
    }

    //
    // hypervisor synthetic MSRs — inject #GP
    //
    if (target_msr >= 0x40000000 && target_msr <= 0x4FFFFFFF)
    {
        NTSTATUS status = STATUS_PRIVILEGED_INSTRUCTION;

        if (g_stealth_cpuid_cache.outer_hypervisor_present &&
            vmexit_try_write_msr(target_msr, msr.Flags, &status))
        {
            vmexit_log_synthetic_msr(TRUE, target_msr, TRUE, status);
            return;
        }

        vmexit_log_synthetic_msr(TRUE, target_msr, FALSE, status);
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    // IA32_FEATURE_CONTROL (locked) + VMX capability MSRs (read-only)
    if (target_msr == IA32_FEATURE_CONTROL ||
        (target_msr >= IA32_VMX_BASIC && target_msr <= 0x493))
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    if ((target_msr <= 0x00001FFF) ||
        ((0xC0000000 <= target_msr) && (target_msr <= 0xC0001FFF)))
    {
        switch (target_msr)
        {
        case IA32_SYSENTER_CS:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, msr.Flags);
            break;

        case IA32_SYSENTER_ESP:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, msr.Flags);
            break;

        case IA32_SYSENTER_EIP:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, msr.Flags);
            break;

        case IA32_GS_BASE:
            __vmx_vmwrite(VMCS_GUEST_GS_BASE, msr.Flags);
            break;

        case IA32_FS_BASE:
            __vmx_vmwrite(VMCS_GUEST_FS_BASE, msr.Flags);
            break;

        default:
            __writemsr(target_msr, msr.Flags);
            break;
        }
    }
    else
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }
}

//
// Defeats: hvdetecc vm.vmxe (checks if CR4 bit 13 is set)
//
//   CR4 guest/host mask has bit 13 set, so guest reads CR4 with VMXE
//   from the read shadow (where it's 0). Guest writes to CR4 that change
//   masked bits cause a VM-exit, which we handle here by keeping VMXE=1
//   in the actual VMCS guest CR4 while the shadow shows VMXE=0.
//

VOID
vmexit_handle_mov_cr(VIRTUAL_MACHINE_STATE * vcpu)
{
    VMX_EXIT_QUALIFICATION_MOV_CR cr_qual;
    PGUEST_REGS                   regs = vcpu->regs;
    UINT64 *                      reg_ptr;

    cr_qual.AsUInt = vcpu->exit_qual;

    switch (cr_qual.GeneralPurposeRegister)
    {
    case 0:  reg_ptr = &regs->rax; break;
    case 1:  reg_ptr = &regs->rcx; break;
    case 2:  reg_ptr = &regs->rdx; break;
    case 3:  reg_ptr = &regs->rbx; break;
    case 4:  reg_ptr = &regs->rsp; break;
    case 5:  reg_ptr = &regs->rbp; break;
    case 6:  reg_ptr = &regs->rsi; break;
    case 7:  reg_ptr = &regs->rdi; break;
    case 8:  reg_ptr = &regs->r8;  break;
    case 9:  reg_ptr = &regs->r9;  break;
    case 10: reg_ptr = &regs->r10; break;
    case 11: reg_ptr = &regs->r11; break;
    case 12: reg_ptr = &regs->r12; break;
    case 13: reg_ptr = &regs->r13; break;
    case 14: reg_ptr = &regs->r14; break;
    case 15: reg_ptr = &regs->r15; break;
    default: reg_ptr = &regs->rax; break;
    }

    switch (cr_qual.AccessType)
    {
    case 0: // MOV to CR
    {
        switch (cr_qual.ControlRegister)
        {
        case 0:
        {
            //
            // MOV to CR0: enforce VMX fixed bits to prevent VM-entry failure.
            // shadow gets the guest's requested value so reads return what the
            // guest wrote (host-owned bits come from shadow, not actual CR0).
            //
            UINT64  desired = *reg_ptr;
            CR_FIXED fixed;
            UINT64  actual = desired;

            fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
            actual |= fixed.Fields.Low;
            fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
            actual &= fixed.Fields.Low;

            __vmx_vmwrite(VMCS_GUEST_CR0, actual);
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, desired);
            break;
        }

        case 3:
        {
            //
            // MOV to CR3: handle pcid no-invalidate (bit 63) and flush tlb
            //
            // with vpid enabled, intercepting mov cr3 prevents the hardware
            // from flushing stale guest tlb entries. must call invvpid to
            // maintain tlb coherency unless the pcid no-invalidate bit is set
            //
            // bit 63 must be 0 in VMCS_GUEST_CR3 for vm-entry to succeed
            //
            UINT64  new_cr3  = *reg_ptr;
            BOOLEAN no_flush = (new_cr3 >> 63) & 1;

            __vmx_vmwrite(VMCS_GUEST_CR3, new_cr3 & ~(1ULL << 63));

            if (!no_flush)
            {
                //
                // prefer RetainingGlobals (type 3) to preserve global kernel
                // tlb entries — matches bare-metal mov cr3 behavior
                //
                INVVPID_DESCRIPTOR desc = {0};
                desc.Vpid = VPID_TAG;

                UINT8 ret;
                if (g_ept->invvpid_single_retaining_globals)
                {
                    ret = asm_invvpid(InvvpidSingleContextRetainingGlobals, &desc);
                }
                else
                {
                    ret = asm_invvpid(InvvpidSingleContext, &desc);
                }

                if (ret != 0)
                {
                    //
                    // fallback: all-contexts flush (always supported)
                    //
                    asm_invvpid(InvvpidAllContexts, &desc);
                }
            }
            break;
        }

        case 8:
            //
            // MOV to CR8 (TPR): pass through directly
            // only bits [3:0] are valid. required when cr8-load exiting
            // is forced by must-be-1 bits
            //
            __writecr8(*reg_ptr & 0xF);
            break;

        case 4:
        {
            //
            // MOV to CR4: enforce VMX fixed bits + stealth VMXE hiding.
            //
            UINT64  desired = *reg_ptr;
            CR_FIXED fixed;

#if STEALTH_HIDE_CR4_VMXE
            if (g_stealth_enabled)
            {
                UINT64 actual = desired | CR4_VMX_ENABLE_FLAG;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
                actual |= fixed.Fields.Low;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
                actual &= fixed.Fields.Low;

                __vmx_vmwrite(VMCS_GUEST_CR4, actual);
                __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, desired & ~CR4_VMX_ENABLE_FLAG);
            }
            else
#endif
            {
                UINT64 actual = desired;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
                actual |= fixed.Fields.Low;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
                actual &= fixed.Fields.Low;

                __vmx_vmwrite(VMCS_GUEST_CR4, actual);
                __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, desired);
            }
            break;
        }

        default:
            break;
        }
        break;
    }
    case 1: // MOV from CR
    {
        switch (cr_qual.ControlRegister)
        {
        case 3:
            __vmx_vmread(VMCS_GUEST_CR3, reg_ptr);
            break;

        case 8:
            *reg_ptr = __readcr8();
            break;

        default:
            break;
        }
        break;
    }
    case 2: // CLTS — clear CR0.TS (bit 3)
    {
        UINT64  guest_cr0 = 0;
        UINT64  shadow    = 0;
        CR_FIXED fixed;

        __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
        __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);

        guest_cr0 &= ~(1ULL << 3);
        shadow    &= ~(1ULL << 3);

        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
        guest_cr0 |= fixed.Fields.Low;
        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
        guest_cr0 &= fixed.Fields.Low;

        __vmx_vmwrite(VMCS_GUEST_CR0, guest_cr0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        break;
    }
    case 3: // LMSW — load machine status word (bits 0-3 of CR0)
    {
        //
        // LMSW loads PE, MP, EM, TS from source data in exit qualification.
        // PE (bit 0) can be set but NOT cleared by LMSW (Intel SDM Vol 2).
        //
        UINT64  guest_cr0 = 0;
        UINT64  shadow    = 0;
        CR_FIXED fixed;
        UINT64  src       = (UINT64)(UINT16)cr_qual.LmswSourceData & 0xFULL;

        __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
        __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);

        //
        // Bits 1-3 (MP, EM, TS): loaded from source
        // Bit 0 (PE): can be set, never cleared — OR with current value
        //
        guest_cr0 = (guest_cr0 & ~0xEULL) | (src & 0xEULL) | ((guest_cr0 | src) & 1ULL);
        shadow    = (shadow    & ~0xEULL) | (src & 0xEULL) | ((shadow    | src) & 1ULL);

        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
        guest_cr0 |= fixed.Fields.Low;
        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
        guest_cr0 &= fixed.Fields.Low;

        __vmx_vmwrite(VMCS_GUEST_CR0, guest_cr0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        break;
    }
    default:
        break;
    }
}

static __forceinline UINT64
vmexit_mask_to_width(UINT64 value, ZyanU8 width)
{
    if (width >= 64)
        return value;

    return value & ((1ULL << width) - 1);
}

static __forceinline INT64
vmexit_sign_extend_to_64(UINT64 value, ZyanU8 width)
{
    if (!width || width >= 64)
        return (INT64)value;

    value = vmexit_mask_to_width(value, width);
    return (INT64)((value ^ (1ULL << (width - 1))) - (1ULL << (width - 1)));
}

static __forceinline ZyanU8
vmexit_bits_to_bytes(ZyanU16 bits)
{
    return (ZyanU8)((bits + 7u) / 8u);
}

static __forceinline BOOLEAN
vmexit_is_high8_register(ZydisRegister reg)
{
    return reg == ZYDIS_REGISTER_AH ||
           reg == ZYDIS_REGISTER_BH ||
           reg == ZYDIS_REGISTER_CH ||
           reg == ZYDIS_REGISTER_DH;
}

static PEPT_HOOK_STATE
vmexit_find_hook_for_pfn(SIZE_T pfn)
{
    if (!g_ept)
        return NULL;

    for (PLIST_ENTRY entry = g_ept->hooked_pages.Flink;
         entry != &g_ept->hooked_pages;
         entry = entry->Flink)
    {
        PEPT_HOOK_STATE hook = CONTAINING_RECORD(entry, EPT_HOOK_STATE, ListEntry);
        if (hook->OriginalPfn == pfn || hook->FakePfn == pfn)
            return hook;
    }

    return NULL;
}

static __forceinline BOOLEAN
vmexit_hook_matches_context(PEPT_HOOK_STATE hook, UINT64 guest_cr3, PVOID guest_page_base)
{
    if (!hook || !hook->Enabled)
        return FALSE;

    return (!hook->TargetCr3 || hook->TargetCr3 == guest_cr3) &&
           (!hook->TargetPageBase || !guest_page_base || hook->TargetPageBase == guest_page_base);
}

#define HV_HOOK_FAULT_FLAG_EXECUTE        0x00000001U
#define HV_HOOK_FAULT_FLAG_READ           0x00000002U
#define HV_HOOK_FAULT_FLAG_WRITE          0x00000004U
#define HV_HOOK_FAULT_FLAG_LINEAR_VALID   0x00000008U
#define HV_HOOK_FAULT_FLAG_CONTEXT_MATCH  0x00000010U

static VOID
vmexit_acquire_hotspot_lock(_Inout_ PEPT_HOOK_STATE hook)
{
    while (InterlockedCompareExchange(&hook->HotspotLock, 1, 0) != 0)
    {
        YieldProcessor();
    }
}

static VOID
vmexit_release_hotspot_lock(_Inout_ PEPT_HOOK_STATE hook)
{
    InterlockedExchange(&hook->HotspotLock, 0);
}

static VOID
vmexit_record_hook_hotspot(
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ LONG flags,
    _In_ UINT64 guest_rip,
    _In_ UINT64 guest_phys,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid)
{
    LONG64 sequence = 0;
    UINT64 sampled_linear = guest_linear_valid ? guest_linear : 0;
    PEPT_HOOK_HOTSPOT_ENTRY empty_slot = NULL;
    PEPT_HOOK_HOTSPOT_ENTRY victim_slot = NULL;

    if (!hook)
        return;

    sequence = InterlockedIncrement64(&hook->HotspotSequence);
    if (EPT_HOOK_HOTSPOT_SAMPLE_EVERY > 1 &&
        (sequence % EPT_HOOK_HOTSPOT_SAMPLE_EVERY) != 0)
    {
        return;
    }

    vmexit_acquire_hotspot_lock(hook);

    for (UINT32 i = 0; i < EPT_HOOK_HOTSPOT_COUNT; i++)
    {
        PEPT_HOOK_HOTSPOT_ENTRY entry = &hook->Hotspots[i];

        if (entry->HitCount == 0)
        {
            if (!empty_slot)
                empty_slot = entry;
            continue;
        }

        if (entry->Rip == guest_rip &&
            entry->GuestLinear == sampled_linear &&
            entry->Flags == (UINT32)flags)
        {
            entry->GuestPhysical = guest_phys;
            entry->HitCount += 1;
            vmexit_release_hotspot_lock(hook);
            return;
        }

        if (!victim_slot || entry->HitCount < victim_slot->HitCount)
            victim_slot = entry;
    }

    if (empty_slot)
    {
        empty_slot->Rip           = guest_rip;
        empty_slot->GuestPhysical = guest_phys;
        empty_slot->GuestLinear   = sampled_linear;
        empty_slot->Flags         = (UINT32)flags;
        empty_slot->Reserved      = 0;
        empty_slot->HitCount      = 1;
        vmexit_release_hotspot_lock(hook);
        return;
    }

    if (victim_slot)
    {
        UINT64 replacement_hits = victim_slot->HitCount + 1;
        victim_slot->Rip           = guest_rip;
        victim_slot->GuestPhysical = guest_phys;
        victim_slot->GuestLinear   = sampled_linear;
        victim_slot->Flags         = (UINT32)flags;
        victim_slot->Reserved      = 0;
        victim_slot->HitCount      = replacement_hits;
    }

    vmexit_release_hotspot_lock(hook);
}

static VOID
vmexit_record_hook_violation(
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ const VMX_EXIT_QUALIFICATION_EPT_VIOLATION *qual,
    _In_ BOOLEAN hook_matches_context,
    _In_ UINT64 guest_rip,
    _In_ UINT64 guest_phys,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid)
{
    LONG flags = 0;

    if (!hook || !qual)
        return;

    if (qual->ExecuteAccess)
    {
        InterlockedIncrement64(&hook->ExecuteViolationCount);
        flags |= HV_HOOK_FAULT_FLAG_EXECUTE;
    }

    if (qual->ReadAccess)
    {
        InterlockedIncrement64(&hook->ReadViolationCount);
        flags |= HV_HOOK_FAULT_FLAG_READ;
    }

    if (qual->WriteAccess)
    {
        InterlockedIncrement64(&hook->WriteViolationCount);
        flags |= HV_HOOK_FAULT_FLAG_WRITE;
    }

    if (!hook_matches_context)
    {
        InterlockedIncrement64(&hook->ContextMismatchCount);
    }
    else
    {
        flags |= HV_HOOK_FAULT_FLAG_CONTEXT_MATCH;
    }

    if (guest_linear_valid)
        flags |= HV_HOOK_FAULT_FLAG_LINEAR_VALID;

    vmexit_record_hook_hotspot(
        hook,
        flags,
        guest_rip,
        guest_phys,
        guest_linear,
        guest_linear_valid);

    InterlockedExchange64(&hook->LastViolationRip, (LONG64)guest_rip);
    InterlockedExchange64(&hook->LastGuestPhysical, (LONG64)guest_phys);
    InterlockedExchange64(&hook->LastGuestLinear, guest_linear_valid ? (LONG64)guest_linear : 0);
    InterlockedExchange(&hook->LastViolationFlags, flags);
}

static VOID
vmexit_acquire_hook_lock(_Inout_ PEPT_HOOK_STATE hook)
{
    while (InterlockedCompareExchange(&hook->AccessLock, 1, 0) != 0)
    {
        YieldProcessor();
    }
}

static VOID
vmexit_release_hook_lock(_Inout_ PEPT_HOOK_STATE hook)
{
    InterlockedExchange(&hook->AccessLock, 0);
}

static VOID
vmexit_sync_fake_page_locked(_Inout_ PEPT_HOOK_STATE hook)
{
    if (!hook->OriginalPageVa || !hook->FakeVa)
        return;

    RtlCopyMemory(hook->FakeVa, hook->OriginalPageVa, PAGE_SIZE);

    for (UINT32 i = 0; i < EPT_HOOK_MAX_PATCHES_PER_PAGE; ++i)
    {
        if (hook->Patches[i].Size == 0)
            continue;

        RtlCopyMemory(
            (PUCHAR)hook->FakeVa + hook->Patches[i].Offset,
            hook->Patches[i].Bytes,
            hook->Patches[i].Size);
    }
}

static VOID
vmexit_sync_fake_page(_Inout_ PEPT_HOOK_STATE hook)
{
    if (!hook)
        return;

    vmexit_acquire_hook_lock(hook);
    vmexit_sync_fake_page_locked(hook);
    vmexit_release_hook_lock(hook);
}

static UINT64 *
vmexit_get_register_slot(_Inout_ VIRTUAL_MACHINE_STATE *vcpu, ZydisRegister reg)
{
    switch (reg)
    {
    case ZYDIS_REGISTER_RAX:
    case ZYDIS_REGISTER_EAX:
    case ZYDIS_REGISTER_AX:
    case ZYDIS_REGISTER_AL:
    case ZYDIS_REGISTER_AH:
        return &vcpu->regs->rax;

    case ZYDIS_REGISTER_RBX:
    case ZYDIS_REGISTER_EBX:
    case ZYDIS_REGISTER_BX:
    case ZYDIS_REGISTER_BL:
    case ZYDIS_REGISTER_BH:
        return &vcpu->regs->rbx;

    case ZYDIS_REGISTER_RCX:
    case ZYDIS_REGISTER_ECX:
    case ZYDIS_REGISTER_CX:
    case ZYDIS_REGISTER_CL:
    case ZYDIS_REGISTER_CH:
        return &vcpu->regs->rcx;

    case ZYDIS_REGISTER_RDX:
    case ZYDIS_REGISTER_EDX:
    case ZYDIS_REGISTER_DX:
    case ZYDIS_REGISTER_DL:
    case ZYDIS_REGISTER_DH:
        return &vcpu->regs->rdx;

    case ZYDIS_REGISTER_RSP:
    case ZYDIS_REGISTER_ESP:
    case ZYDIS_REGISTER_SP:
    case ZYDIS_REGISTER_SPL:
        return &vcpu->regs->rsp;

    case ZYDIS_REGISTER_RBP:
    case ZYDIS_REGISTER_EBP:
    case ZYDIS_REGISTER_BP:
    case ZYDIS_REGISTER_BPL:
        return &vcpu->regs->rbp;

    case ZYDIS_REGISTER_RSI:
    case ZYDIS_REGISTER_ESI:
    case ZYDIS_REGISTER_SI:
    case ZYDIS_REGISTER_SIL:
        return &vcpu->regs->rsi;

    case ZYDIS_REGISTER_RDI:
    case ZYDIS_REGISTER_EDI:
    case ZYDIS_REGISTER_DI:
    case ZYDIS_REGISTER_DIL:
        return &vcpu->regs->rdi;

    case ZYDIS_REGISTER_R8:
    case ZYDIS_REGISTER_R8D:
    case ZYDIS_REGISTER_R8W:
    case ZYDIS_REGISTER_R8B:
        return &vcpu->regs->r8;

    case ZYDIS_REGISTER_R9:
    case ZYDIS_REGISTER_R9D:
    case ZYDIS_REGISTER_R9W:
    case ZYDIS_REGISTER_R9B:
        return &vcpu->regs->r9;

    case ZYDIS_REGISTER_R10:
    case ZYDIS_REGISTER_R10D:
    case ZYDIS_REGISTER_R10W:
    case ZYDIS_REGISTER_R10B:
        return &vcpu->regs->r10;

    case ZYDIS_REGISTER_R11:
    case ZYDIS_REGISTER_R11D:
    case ZYDIS_REGISTER_R11W:
    case ZYDIS_REGISTER_R11B:
        return &vcpu->regs->r11;

    case ZYDIS_REGISTER_R12:
    case ZYDIS_REGISTER_R12D:
    case ZYDIS_REGISTER_R12W:
    case ZYDIS_REGISTER_R12B:
        return &vcpu->regs->r12;

    case ZYDIS_REGISTER_R13:
    case ZYDIS_REGISTER_R13D:
    case ZYDIS_REGISTER_R13W:
    case ZYDIS_REGISTER_R13B:
        return &vcpu->regs->r13;

    case ZYDIS_REGISTER_R14:
    case ZYDIS_REGISTER_R14D:
    case ZYDIS_REGISTER_R14W:
    case ZYDIS_REGISTER_R14B:
        return &vcpu->regs->r14;

    case ZYDIS_REGISTER_R15:
    case ZYDIS_REGISTER_R15D:
    case ZYDIS_REGISTER_R15W:
    case ZYDIS_REGISTER_R15B:
        return &vcpu->regs->r15;

    default:
        return NULL;
    }
}

static BOOLEAN
vmexit_read_register_value(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _In_ ZydisMachineMode machine_mode,
    _In_ ZydisRegister reg,
    _Out_ UINT64 *value)
{
    ZyanU16 width = ZydisRegisterGetWidth(machine_mode, reg);
    UINT64 *slot = vmexit_get_register_slot(vcpu, reg);
    UINT64 raw = 0;

    if (reg == ZYDIS_REGISTER_RIP || reg == ZYDIS_REGISTER_EIP || reg == ZYDIS_REGISTER_IP)
    {
        raw = vcpu->vmexit_rip;
    }
    else if (slot)
    {
        raw = *slot;
    }
    else
    {
        return FALSE;
    }

    if (vmexit_is_high8_register(reg))
    {
        *value = (raw >> 8) & 0xFF;
        return TRUE;
    }

    *value = vmexit_mask_to_width(raw, (ZyanU8)width);
    return TRUE;
}

static BOOLEAN
vmexit_write_register_value(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _In_ ZydisMachineMode machine_mode,
    _In_ ZydisRegister reg,
    _In_ UINT64 value)
{
    UINT64 *slot = vmexit_get_register_slot(vcpu, reg);
    ZyanU16 width = ZydisRegisterGetWidth(machine_mode, reg);

    if (!slot)
        return FALSE;

    if (vmexit_is_high8_register(reg))
    {
        *slot = (*slot & ~0x0000FF00ULL) | ((value & 0xFF) << 8);
    }
    else
    {
        switch (width)
        {
        case 8:
            *slot = (*slot & ~0xFFULL) | (value & 0xFF);
            break;
        case 16:
            *slot = (*slot & ~0xFFFFULL) | (value & 0xFFFF);
            break;
        case 32:
            *slot = value & 0xFFFFFFFFULL;
            break;
        case 64:
            *slot = value;
            break;
        default:
            return FALSE;
        }
    }

    if (slot == &vcpu->regs->rsp)
        __vmx_vmwrite(VMCS_GUEST_RSP, *slot);

    return TRUE;
}

static UINT64
vmexit_get_segment_base(_In_ ZydisRegister seg)
{
    UINT64 base = 0;

    switch (seg)
    {
    case ZYDIS_REGISTER_ES:
        __vmx_vmread(VMCS_GUEST_ES_BASE, &base);
        break;
    case ZYDIS_REGISTER_CS:
        __vmx_vmread(VMCS_GUEST_CS_BASE, &base);
        break;
    case ZYDIS_REGISTER_SS:
        __vmx_vmread(VMCS_GUEST_SS_BASE, &base);
        break;
    case ZYDIS_REGISTER_DS:
        __vmx_vmread(VMCS_GUEST_DS_BASE, &base);
        break;
    case ZYDIS_REGISTER_FS:
        __vmx_vmread(VMCS_GUEST_FS_BASE, &base);
        break;
    case ZYDIS_REGISTER_GS:
        __vmx_vmread(VMCS_GUEST_GS_BASE, &base);
        break;
    default:
        base = 0;
        break;
    }

    return base;
}

static VOID
vmexit_get_zydis_mode(
    _Out_ ZydisMachineMode *machine_mode,
    _Out_ ZydisStackWidth *stack_width)
{
    UINT64 cs_ar_raw = 0;
    UINT64 ss_ar_raw = 0;
    UINT64 efer_raw = 0;
    VMX_SEGMENT_ACCESS_RIGHTS cs_ar;
    VMX_SEGMENT_ACCESS_RIGHTS ss_ar;
    IA32_EFER_REGISTER efer;

    __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &cs_ar_raw);
    __vmx_vmread(VMCS_GUEST_SS_ACCESS_RIGHTS, &ss_ar_raw);
    __vmx_vmread(VMCS_GUEST_EFER, &efer_raw);

    cs_ar.AsUInt = (UINT32)cs_ar_raw;
    ss_ar.AsUInt = (UINT32)ss_ar_raw;
    efer.AsUInt = efer_raw;

    if (cs_ar.LongMode)
    {
        *machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        *stack_width = ZYDIS_STACK_WIDTH_64;
        return;
    }

    if (efer.Ia32eModeActive)
        *machine_mode = cs_ar.DefaultBig ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32 : ZYDIS_MACHINE_MODE_LONG_COMPAT_16;
    else
        *machine_mode = cs_ar.DefaultBig ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LEGACY_16;

    *stack_width = ss_ar.DefaultBig ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_16;
}

static UINT8
vmexit_get_guest_cpl(VOID)
{
    size_t guest_cs_selector = 0;
    __vmx_vmread(VMCS_GUEST_CS_SELECTOR, &guest_cs_selector);
    return (UINT8)(guest_cs_selector & 0x3);
}

static BOOLEAN
vmexit_guest_is_user_mode(VOID)
{
    return vmexit_get_guest_cpl() == 3;
}

static BOOLEAN
vmexit_translate_guest_linear(
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_linear,
    _Out_ UINT64 *guest_phys)
{
    UINT64 guest_cr0 = 0;
    PUINT64 table = NULL;
    UINT64 entry = 0;

    __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
    if (!(guest_cr0 & HV_CR0_PG_FLAG))
    {
        *guest_phys = guest_linear;
        return TRUE;
    }

    table = (PUINT64)pa_to_va(guest_cr3 & HV_GUEST_PTE_PFN_MASK);
    if (!table)
        return FALSE;

    entry = table[(guest_linear >> 39) & 0x1FF];
    if (!(entry & HV_GUEST_PTE_PRESENT))
        return FALSE;

    table = (PUINT64)pa_to_va(entry & HV_GUEST_PTE_PFN_MASK);
    if (!table)
        return FALSE;

    entry = table[(guest_linear >> 30) & 0x1FF];
    if (!(entry & HV_GUEST_PTE_PRESENT))
        return FALSE;

    if (entry & HV_GUEST_PTE_LARGE_PAGE)
    {
        *guest_phys = (entry & HV_GUEST_PTE_PFN_MASK) + (guest_linear & ((1ULL << 30) - 1));
        return TRUE;
    }

    table = (PUINT64)pa_to_va(entry & HV_GUEST_PTE_PFN_MASK);
    if (!table)
        return FALSE;

    entry = table[(guest_linear >> 21) & 0x1FF];
    if (!(entry & HV_GUEST_PTE_PRESENT))
        return FALSE;

    if (entry & HV_GUEST_PTE_LARGE_PAGE)
    {
        *guest_phys = (entry & HV_GUEST_PTE_PFN_MASK) + (guest_linear & ((1ULL << 21) - 1));
        return TRUE;
    }

    table = (PUINT64)pa_to_va(entry & HV_GUEST_PTE_PFN_MASK);
    if (!table)
        return FALSE;

    entry = table[(guest_linear >> 12) & 0x1FF];
    if (!(entry & HV_GUEST_PTE_PRESENT))
        return FALSE;

    *guest_phys = (entry & HV_GUEST_PTE_PFN_MASK) + (guest_linear & (PAGE_SIZE - 1));
    return TRUE;
}

static BOOLEAN
vmexit_copy_guest_linear(
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_linear,
    _Inout_updates_bytes_(size) PVOID buffer,
    _In_ SIZE_T size,
    _In_ BOOLEAN write_to_guest)
{
    PUCHAR cursor = (PUCHAR)buffer;
    SIZE_T remaining = size;

    while (remaining > 0)
    {
        UINT64 guest_phys = 0;
        PUCHAR host_page = NULL;
        SIZE_T page_offset = BYTE_OFFSET(guest_linear);
        SIZE_T chunk = PAGE_SIZE - page_offset;

        if (!vmexit_translate_guest_linear(guest_cr3, guest_linear, &guest_phys))
            return FALSE;

        host_page = (PUCHAR)pa_to_va(guest_phys & ~(UINT64)(PAGE_SIZE - 1));
        if (!host_page)
            return FALSE;

        if (chunk > remaining)
            chunk = remaining;

        if (write_to_guest)
            RtlCopyMemory(host_page + page_offset, cursor, chunk);
        else
            RtlCopyMemory(cursor, host_page + page_offset, chunk);

        cursor += chunk;
        guest_linear += chunk;
        remaining -= chunk;
    }

    return TRUE;
}

static BOOLEAN
vmexit_copy_guest_instruction_bytes(
    _In_ VIRTUAL_MACHINE_STATE *vcpu,
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_linear,
    _Out_writes_bytes_(size) PVOID buffer,
    _In_ SIZE_T size)
{
    PUCHAR cursor = (PUCHAR)buffer;
    SIZE_T remaining = size;

    while (remaining > 0)
    {
        UINT64 guest_phys = 0;
        PUCHAR source_page = NULL;
        SIZE_T page_offset = BYTE_OFFSET(guest_linear);
        SIZE_T chunk = PAGE_SIZE - page_offset;
        SIZE_T pfn = 0;
        PEPT_HOOK_STATE code_hook = NULL;
        PVOID code_page_base = PAGE_ALIGN((PVOID)(ULONG_PTR)guest_linear);

        if (!vmexit_translate_guest_linear(guest_cr3, guest_linear, &guest_phys))
            return FALSE;

        pfn = guest_phys / PAGE_SIZE;
        code_hook = vmexit_find_hook_for_pfn(pfn);
        if (code_hook && vmexit_hook_matches_context(code_hook, guest_cr3, code_page_base))
            source_page = (PUCHAR)code_hook->FakeVa;
        else
            source_page = (PUCHAR)pa_to_va(guest_phys & ~(UINT64)(PAGE_SIZE - 1));

        if (!source_page)
            return FALSE;

        if (chunk > remaining)
            chunk = remaining;

        RtlCopyMemory(cursor, source_page + page_offset, chunk);
        cursor += chunk;
        guest_linear += chunk;
        remaining -= chunk;
    }

    UNREFERENCED_PARAMETER(vcpu);
    return TRUE;
}

static BOOLEAN
vmexit_calculate_linear_address(
    _In_ VIRTUAL_MACHINE_STATE *vcpu,
    _In_ ZydisMachineMode machine_mode,
    _In_ const ZydisDecodedInstruction *instruction,
    _In_ const ZydisDecodedOperand *operand,
    _In_ UINT64 instruction_rip,
    _Out_ UINT64 *linear_address)
{
    UINT64 segment_base = vmexit_get_segment_base(operand->mem.segment);
    UINT64 base = 0;
    UINT64 index = 0;
    UINT64 offset = 0;

    if (operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
        return FALSE;

    if (operand->mem.base == ZYDIS_REGISTER_RIP ||
        operand->mem.base == ZYDIS_REGISTER_EIP ||
        operand->mem.base == ZYDIS_REGISTER_IP)
    {
        base = instruction_rip + instruction->length;
    }
    else if (operand->mem.base != ZYDIS_REGISTER_NONE &&
             !vmexit_read_register_value(vcpu, machine_mode, operand->mem.base, &base))
    {
        return FALSE;
    }

    if (operand->mem.index != ZYDIS_REGISTER_NONE &&
        !vmexit_read_register_value(vcpu, machine_mode, operand->mem.index, &index))
    {
        return FALSE;
    }

    offset = base + (index * operand->mem.scale);
    if (operand->mem.disp.has_displacement)
        offset += (UINT64)operand->mem.disp.value;

    switch (instruction->address_width)
    {
    case 16:
        offset = (UINT16)offset;
        break;
    case 32:
        offset = (UINT32)offset;
        break;
    default:
        break;
    }

    *linear_address = segment_base + offset;
    return TRUE;
}

static __forceinline BOOLEAN
vmexit_even_parity8(UCHAR value)
{
    value ^= (UCHAR)(value >> 4);
    value ^= (UCHAR)(value >> 2);
    value ^= (UCHAR)(value >> 1);
    return (value & 1) == 0;
}

static VOID
vmexit_write_test_flags(_In_ UINT64 lhs, _In_ UINT64 rhs, _In_ ZyanU8 width)
{
    UINT64 rflags = 0;
    UINT64 result = vmexit_mask_to_width(lhs & rhs, width);
    UINT64 sign_mask = (width >= 64) ? (1ULL << 63) : (1ULL << (width - 1));

    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
    rflags &= ~(HV_RFLAGS_CF | HV_RFLAGS_PF | HV_RFLAGS_ZF | HV_RFLAGS_SF | HV_RFLAGS_OF);

    if (vmexit_even_parity8((UCHAR)result))
        rflags |= HV_RFLAGS_PF;
    if (result == 0)
        rflags |= HV_RFLAGS_ZF;
    if (result & sign_mask)
        rflags |= HV_RFLAGS_SF;

    __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags);
}

static VOID
vmexit_write_cmp_flags(_In_ UINT64 lhs, _In_ UINT64 rhs, _In_ ZyanU8 width)
{
    UINT64 rflags = 0;
    UINT64 lhs_masked = vmexit_mask_to_width(lhs, width);
    UINT64 rhs_masked = vmexit_mask_to_width(rhs, width);
    UINT64 result = vmexit_mask_to_width(lhs_masked - rhs_masked, width);
    UINT64 sign_mask = (width >= 64) ? (1ULL << 63) : (1ULL << (width - 1));

    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
    rflags &= ~(HV_RFLAGS_CF | HV_RFLAGS_PF | HV_RFLAGS_AF | HV_RFLAGS_ZF | HV_RFLAGS_SF | HV_RFLAGS_OF);

    if (lhs_masked < rhs_masked)
        rflags |= HV_RFLAGS_CF;
    if (vmexit_even_parity8((UCHAR)result))
        rflags |= HV_RFLAGS_PF;
    if ((lhs_masked ^ rhs_masked ^ result) & 0x10)
        rflags |= HV_RFLAGS_AF;
    if (result == 0)
        rflags |= HV_RFLAGS_ZF;
    if (result & sign_mask)
        rflags |= HV_RFLAGS_SF;
    if (((lhs_masked ^ rhs_masked) & (lhs_masked ^ result) & sign_mask) != 0)
        rflags |= HV_RFLAGS_OF;

    __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags);
}

static VOID
vmexit_write_logic_flags(_In_ UINT64 result, _In_ ZyanU8 width)
{
    UINT64 rflags = 0;
    UINT64 masked = vmexit_mask_to_width(result, width);
    UINT64 sign_mask = (width >= 64) ? (1ULL << 63) : (1ULL << (width - 1));

    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
    rflags &= ~(HV_RFLAGS_CF | HV_RFLAGS_PF | HV_RFLAGS_ZF | HV_RFLAGS_SF | HV_RFLAGS_OF);

    if (vmexit_even_parity8((UCHAR)masked))
        rflags |= HV_RFLAGS_PF;
    if (masked == 0)
        rflags |= HV_RFLAGS_ZF;
    if (masked & sign_mask)
        rflags |= HV_RFLAGS_SF;

    __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags);
}

static VOID
vmexit_write_add_flags(_In_ UINT64 lhs, _In_ UINT64 rhs, _In_ UINT64 result, _In_ ZyanU8 width)
{
    UINT64 rflags = 0;
    UINT64 lhs_masked = vmexit_mask_to_width(lhs, width);
    UINT64 rhs_masked = vmexit_mask_to_width(rhs, width);
    UINT64 result_masked = vmexit_mask_to_width(result, width);
    UINT64 sign_mask = (width >= 64) ? (1ULL << 63) : (1ULL << (width - 1));

    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
    rflags &= ~(HV_RFLAGS_CF | HV_RFLAGS_PF | HV_RFLAGS_AF | HV_RFLAGS_ZF | HV_RFLAGS_SF | HV_RFLAGS_OF);

    if (result_masked < lhs_masked)
        rflags |= HV_RFLAGS_CF;
    if (vmexit_even_parity8((UCHAR)result_masked))
        rflags |= HV_RFLAGS_PF;
    if ((lhs_masked ^ rhs_masked ^ result_masked) & 0x10)
        rflags |= HV_RFLAGS_AF;
    if (result_masked == 0)
        rflags |= HV_RFLAGS_ZF;
    if (result_masked & sign_mask)
        rflags |= HV_RFLAGS_SF;
    if ((~(lhs_masked ^ rhs_masked) & (lhs_masked ^ result_masked) & sign_mask) != 0)
        rflags |= HV_RFLAGS_OF;

    __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags);
}

static VOID
vmexit_restore_carry_flag(_In_ UINT64 old_rflags)
{
    UINT64 rflags = 0;

    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
    rflags = (rflags & ~HV_RFLAGS_CF) | (old_rflags & HV_RFLAGS_CF);
    __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags);
}

static BOOLEAN
vmexit_read_memory_operand(
    _In_ UINT64 guest_cr3,
    _In_ UINT64 mem_linear,
    _In_ const ZydisDecodedOperand *operand,
    _Out_ UINT64 *value)
{
    ZyanU8 bytes = vmexit_bits_to_bytes(operand->size);

    *value = 0;
    if (!bytes || bytes > sizeof(*value))
        return FALSE;

    if (!vmexit_copy_guest_linear(guest_cr3, mem_linear, value, bytes, FALSE))
        return FALSE;

    *value = vmexit_mask_to_width(*value, (ZyanU8)operand->size);
    return TRUE;
}

static BOOLEAN
vmexit_write_memory_operand(
    _In_ UINT64 guest_cr3,
    _In_ UINT64 mem_linear,
    _In_ const ZydisDecodedOperand *operand,
    _In_ UINT64 value)
{
    ZyanU8 bytes = vmexit_bits_to_bytes(operand->size);
    UINT64 masked = vmexit_mask_to_width(value, (ZyanU8)operand->size);

    if (!bytes || bytes > sizeof(masked))
        return FALSE;

    return vmexit_copy_guest_linear(guest_cr3, mem_linear, &masked, bytes, TRUE);
}

static BOOLEAN
vmexit_get_effective_stack_register(
    _In_ ZyanU8 stack_width,
    _Out_ ZydisRegister *stack_reg)
{
    switch (stack_width)
    {
    case 16:
        *stack_reg = ZYDIS_REGISTER_SP;
        return TRUE;
    case 32:
        *stack_reg = ZYDIS_REGISTER_ESP;
        return TRUE;
    case 64:
        *stack_reg = ZYDIS_REGISTER_RSP;
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN
vmexit_push_value_to_guest_stack(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _In_ UINT64 guest_cr3,
    _In_ const ZydisDecodedInstruction *instruction,
    _In_ UINT64 value,
    _In_ ZyanU8 push_width_bytes)
{
    UINT64 rsp_value = 0;
    UINT64 new_rsp = 0;
    UINT64 stack_linear = 0;
    ZydisRegister stack_reg;

    if (!push_width_bytes ||
        !vmexit_get_effective_stack_register((ZyanU8)instruction->stack_width, &stack_reg) ||
        !vmexit_read_register_value(vcpu, instruction->machine_mode, stack_reg, &rsp_value))
    {
        return FALSE;
    }

    new_rsp = vmexit_mask_to_width(rsp_value - push_width_bytes, (ZyanU8)instruction->stack_width);
    stack_linear = vmexit_get_segment_base(ZYDIS_REGISTER_SS) + new_rsp;

    if (!vmexit_copy_guest_linear(guest_cr3, stack_linear, &value, push_width_bytes, TRUE))
        return FALSE;

    return vmexit_write_register_value(vcpu, instruction->machine_mode, stack_reg, new_rsp);
}

static __forceinline BOOLEAN
vmexit_is_cmov_mnemonic(_In_ ZydisMnemonic mnemonic)
{
    switch (mnemonic)
    {
    case ZYDIS_MNEMONIC_CMOVB:
    case ZYDIS_MNEMONIC_CMOVBE:
    case ZYDIS_MNEMONIC_CMOVL:
    case ZYDIS_MNEMONIC_CMOVLE:
    case ZYDIS_MNEMONIC_CMOVNB:
    case ZYDIS_MNEMONIC_CMOVNBE:
    case ZYDIS_MNEMONIC_CMOVNL:
    case ZYDIS_MNEMONIC_CMOVNLE:
    case ZYDIS_MNEMONIC_CMOVNO:
    case ZYDIS_MNEMONIC_CMOVNP:
    case ZYDIS_MNEMONIC_CMOVNS:
    case ZYDIS_MNEMONIC_CMOVNZ:
    case ZYDIS_MNEMONIC_CMOVO:
    case ZYDIS_MNEMONIC_CMOVP:
    case ZYDIS_MNEMONIC_CMOVS:
    case ZYDIS_MNEMONIC_CMOVZ:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN
vmexit_evaluate_condition(_In_ ZydisMnemonic mnemonic)
{
    UINT64 rflags = 0;
    BOOLEAN cf;
    BOOLEAN zf;
    BOOLEAN sf;
    BOOLEAN of;
    BOOLEAN pf;

    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
    cf = !!(rflags & HV_RFLAGS_CF);
    zf = !!(rflags & HV_RFLAGS_ZF);
    sf = !!(rflags & HV_RFLAGS_SF);
    of = !!(rflags & HV_RFLAGS_OF);
    pf = !!(rflags & HV_RFLAGS_PF);

    switch (mnemonic)
    {
    case ZYDIS_MNEMONIC_CMOVB:   return cf;
    case ZYDIS_MNEMONIC_CMOVBE:  return cf || zf;
    case ZYDIS_MNEMONIC_CMOVL:   return sf != of;
    case ZYDIS_MNEMONIC_CMOVLE:  return zf || (sf != of);
    case ZYDIS_MNEMONIC_CMOVNB:  return !cf;
    case ZYDIS_MNEMONIC_CMOVNBE: return !cf && !zf;
    case ZYDIS_MNEMONIC_CMOVNL:  return sf == of;
    case ZYDIS_MNEMONIC_CMOVNLE: return !zf && (sf == of);
    case ZYDIS_MNEMONIC_CMOVNO:  return !of;
    case ZYDIS_MNEMONIC_CMOVNP:  return !pf;
    case ZYDIS_MNEMONIC_CMOVNS:  return !sf;
    case ZYDIS_MNEMONIC_CMOVNZ:  return !zf;
    case ZYDIS_MNEMONIC_CMOVO:   return of;
    case ZYDIS_MNEMONIC_CMOVP:   return pf;
    case ZYDIS_MNEMONIC_CMOVS:   return sf;
    case ZYDIS_MNEMONIC_CMOVZ:   return zf;
    default:
        return FALSE;
    }
}

static BOOLEAN
vmexit_decode_instruction(
    _In_ VIRTUAL_MACHINE_STATE *vcpu,
    _In_ UINT64 guest_cr3,
    _Out_ ZydisDecodedInstruction *instruction,
    _Out_writes_(ZYDIS_MAX_OPERAND_COUNT) ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT])
{
    ZydisDecoder decoder;
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    UCHAR instruction_bytes[ZYDIS_MAX_INSTRUCTION_LENGTH] = {0};
    ZyanStatus status;

    vmexit_get_zydis_mode(&machine_mode, &stack_width);
    if (!vmexit_copy_guest_instruction_bytes(
            vcpu,
            guest_cr3,
            vcpu->vmexit_rip,
            instruction_bytes,
            sizeof(instruction_bytes)))
    {
        return FALSE;
    }

    status = ZydisDecoderInit(&decoder, machine_mode, stack_width);
    if (ZYAN_FAILED(status))
        return FALSE;

    status = ZydisDecoderDecodeFull(
        &decoder,
        instruction_bytes,
        sizeof(instruction_bytes),
        instruction,
        operands);

    return ZYAN_SUCCESS(status);
}

static BOOLEAN
vmexit_is_32bit_guest_mode(_In_ const ZydisDecodedInstruction *instruction)
{
    if (!instruction)
        return FALSE;

    return instruction->machine_mode == ZYDIS_MACHINE_MODE_LONG_COMPAT_32 ||
           instruction->machine_mode == ZYDIS_MACHINE_MODE_LEGACY_32;
}

static __forceinline UINT32
vmexit_read_u32le(_In_reads_bytes_(4) const UCHAR *bytes)
{
    return (UINT32)bytes[0] |
           ((UINT32)bytes[1] << 8) |
           ((UINT32)bytes[2] << 16) |
           ((UINT32)bytes[3] << 24);
}

static ZydisRegister
vmexit_get_32bit_gpr_by_index(_In_ UCHAR index)
{
    switch (index & 0x7)
    {
    case 0: return ZYDIS_REGISTER_EAX;
    case 1: return ZYDIS_REGISTER_ECX;
    case 2: return ZYDIS_REGISTER_EDX;
    case 3: return ZYDIS_REGISTER_EBX;
    case 4: return ZYDIS_REGISTER_ESP;
    case 5: return ZYDIS_REGISTER_EBP;
    case 6: return ZYDIS_REGISTER_ESI;
    case 7: return ZYDIS_REGISTER_EDI;
    default: return ZYDIS_REGISTER_NONE;
    }
}

static BOOLEAN
vmexit_try_emulate_ff_raw_32(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_phys,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid,
    _Out_ BOOLEAN *advance_rip)
{
    UCHAR bytes[16] = { 0 };
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    size_t pos = 0;
    BOOLEAN address_size_override = FALSE;
    UCHAR modrm;
    UCHAR mod;
    UCHAR opcode_extension;
    UCHAR rm;
    UCHAR sib = 0;
    UCHAR scale = 1;
    BOOLEAN has_sib = FALSE;
    BOOLEAN has_base = FALSE;
    BOOLEAN has_index = FALSE;
    ZydisRegister base_reg = ZYDIS_REGISTER_NONE;
    ZydisRegister index_reg = ZYDIS_REGISTER_NONE;
    ZydisRegister default_segment = ZYDIS_REGISTER_DS;
    INT64 displacement = 0;
    UINT64 base_value = 0;
    UINT64 index_value = 0;
    UINT64 mem_linear = 0;
    UINT64 translated_phys = 0;
    UINT32 target = 0;

    if (!vcpu || !advance_rip)
        return FALSE;

    vmexit_get_zydis_mode(&machine_mode, &stack_width);
    if (machine_mode != ZYDIS_MACHINE_MODE_LONG_COMPAT_32 &&
        machine_mode != ZYDIS_MACHINE_MODE_LEGACY_32)
    {
        if (hook) InterlockedIncrement64(&hook->FfRawFailMode);
        return FALSE;
    }

    if (!vmexit_copy_guest_instruction_bytes(vcpu, guest_cr3, vcpu->vmexit_rip, bytes, sizeof(bytes)))
    {
        if (hook) InterlockedIncrement64(&hook->FfRawFailInsnRead);
        return FALSE;
    }

    while (pos < sizeof(bytes))
    {
        UCHAR prefix = bytes[pos];

        if (prefix == 0x66)
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailOpcode);
            return FALSE;
        }

        if (prefix == 0x67)
        {
            address_size_override = TRUE;
            pos++;
            continue;
        }

        if (prefix == 0xF0 || prefix == 0xF2 || prefix == 0xF3 ||
            prefix == 0x2E || prefix == 0x36 || prefix == 0x3E ||
            prefix == 0x26 || prefix == 0x64 || prefix == 0x65)
        {
            pos++;
            continue;
        }

        break;
    }

    if (address_size_override || pos + 2 > sizeof(bytes) || bytes[pos] != 0xFF)
    {
        if (hook) InterlockedIncrement64(&hook->FfRawFailOpcode);
        return FALSE;
    }

    modrm = bytes[pos + 1];
    mod = (UCHAR)((modrm >> 6) & 0x3);
    opcode_extension = (UCHAR)((modrm >> 3) & 0x7);
    rm = (UCHAR)(modrm & 0x7);
    pos += 2;

    if ((opcode_extension != 2 && opcode_extension != 4) || mod == 3)
    {
        if (hook) InterlockedIncrement64(&hook->FfRawFailOpcode);
        return FALSE;
    }

    if (rm == 4)
    {
        if (pos >= sizeof(bytes))
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailOpcode);
            return FALSE;
        }

        sib = bytes[pos++];
        has_sib = TRUE;
        scale = (UCHAR)(1U << ((sib >> 6) & 0x3));

        if (((sib >> 3) & 0x7) != 4)
        {
            has_index = TRUE;
            index_reg = vmexit_get_32bit_gpr_by_index((UCHAR)((sib >> 3) & 0x7));
        }

        if ((sib & 0x7) == 5 && mod == 0)
        {
            if (pos + 4 > sizeof(bytes))
            {
                if (hook) InterlockedIncrement64(&hook->FfRawFailOpcode);
                return FALSE;
            }
            displacement = (INT32)vmexit_read_u32le(&bytes[pos]);
            pos += 4;
        }
        else
        {
            has_base = TRUE;
            base_reg = vmexit_get_32bit_gpr_by_index((UCHAR)(sib & 0x7));
        }
    }
    else if (mod == 0 && rm == 5)
    {
        if (pos + 4 > sizeof(bytes))
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailOpcode);
            return FALSE;
        }
        displacement = (INT32)vmexit_read_u32le(&bytes[pos]);
        pos += 4;
    }
    else
    {
        has_base = TRUE;
        base_reg = vmexit_get_32bit_gpr_by_index(rm);
    }

    if (mod == 1)
    {
        if (pos + 1 > sizeof(bytes))
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailOpcode);
            return FALSE;
        }
        displacement += (CHAR)bytes[pos];
        pos += 1;
    }
    else if (mod == 2)
    {
        if (pos + 4 > sizeof(bytes))
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailOpcode);
            return FALSE;
        }
        displacement += (INT32)vmexit_read_u32le(&bytes[pos]);
        pos += 4;
    }

    if (guest_linear_valid)
    {
        mem_linear = guest_linear;
    }
    else
    {
        if (has_base)
        {
            if (base_reg == ZYDIS_REGISTER_ESP || base_reg == ZYDIS_REGISTER_EBP)
                default_segment = ZYDIS_REGISTER_SS;

            if (!vmexit_read_register_value(vcpu, machine_mode, base_reg, &base_value))
            {
                if (hook) InterlockedIncrement64(&hook->FfRawFailAddrCalc);
                return FALSE;
            }
        }

        if (has_index)
        {
            if (!vmexit_read_register_value(vcpu, machine_mode, index_reg, &index_value))
            {
                if (hook) InterlockedIncrement64(&hook->FfRawFailAddrCalc);
                return FALSE;
            }
        }

        mem_linear = vmexit_get_segment_base(default_segment) +
                     (UINT32)(base_value + (index_value * scale) + displacement);

        if (!vmexit_translate_guest_linear(guest_cr3, mem_linear, &translated_phys))
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailAddrCalc);
            return FALSE;
        }

        if (translated_phys != guest_phys)
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailAddrCalc);
            return FALSE;
        }
    }

    if (!vmexit_copy_guest_linear(guest_cr3, mem_linear, &target, sizeof(target), FALSE))
    {
        if (hook) InterlockedIncrement64(&hook->FfRawFailTargetRead);
        return FALSE;
    }

    if (opcode_extension == 2)
    {
        UINT64 esp = 0;
        UINT32 new_esp = 0;
        UINT64 stack_linear = 0;
        UINT32 return_address = (UINT32)(vcpu->vmexit_rip + pos);

        if (!vmexit_read_register_value(vcpu, machine_mode, ZYDIS_REGISTER_ESP, &esp))
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailStack);
            return FALSE;
        }

        new_esp = (UINT32)((UINT32)esp - sizeof(UINT32));
        stack_linear = vmexit_get_segment_base(ZYDIS_REGISTER_SS) + new_esp;

        if (!vmexit_copy_guest_linear(guest_cr3, stack_linear, &return_address, sizeof(return_address), TRUE))
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailStack);
            return FALSE;
        }

        if (!vmexit_write_register_value(vcpu, machine_mode, ZYDIS_REGISTER_ESP, new_esp))
        {
            if (hook) InterlockedIncrement64(&hook->FfRawFailStack);
            return FALSE;
        }
    }

    __vmx_vmwrite(VMCS_GUEST_RIP, target);
    vcpu->vmexit_rip = target;
    *advance_rip = FALSE;

    if (hook) InterlockedIncrement64(&hook->FfRawSuccess);
    UNREFERENCED_PARAMETER(stack_width);
    UNREFERENCED_PARAMETER(has_sib);
    return TRUE;
}

static BOOLEAN
vmexit_parse_memory_modrm_length_32(
    _In_reads_bytes_(byte_count) const UCHAR *bytes,
    _In_ SIZE_T byte_count,
    _In_ SIZE_T modrm_pos,
    _Out_ UCHAR *modrm_out,
    _Out_ SIZE_T *insn_len_out)
{
    UCHAR modrm;
    UCHAR mod;
    UCHAR rm;
    SIZE_T pos;

    if (!bytes || !modrm_out || !insn_len_out || modrm_pos >= byte_count)
        return FALSE;

    modrm = bytes[modrm_pos];
    mod = (UCHAR)((modrm >> 6) & 0x3);
    rm = (UCHAR)(modrm & 0x7);
    pos = modrm_pos + 1;

    if (mod == 3)
        return FALSE;

    if (rm == 4)
    {
        UCHAR sib;

        if (pos >= byte_count)
            return FALSE;

        sib = bytes[pos++];
        if ((sib & 0x7) == 5 && mod == 0)
        {
            if (pos + 4 > byte_count)
                return FALSE;
            pos += 4;
        }
    }
    else if (mod == 0 && rm == 5)
    {
        if (pos + 4 > byte_count)
            return FALSE;
        pos += 4;
    }

    if (mod == 1)
    {
        if (pos + 1 > byte_count)
            return FALSE;
        pos += 1;
    }
    else if (mod == 2)
    {
        if (pos + 4 > byte_count)
            return FALSE;
        pos += 4;
    }

    *modrm_out = modrm;
    *insn_len_out = pos;
    return TRUE;
}

static BOOLEAN
vmexit_try_emulate_pre_scanned_fast_rule_32(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid,
    _Out_ BOOLEAN *advance_rip)
{
    UCHAR bytes[8] = { 0 };
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    UINT16 rip_offset;
    UINT16 gla_offset;

    if (!vcpu || !hook || !advance_rip || !guest_linear_valid || hook->FastRuleCount == 0)
        return FALSE;

    vmexit_get_zydis_mode(&machine_mode, &stack_width);
    if (machine_mode != ZYDIS_MACHINE_MODE_LONG_COMPAT_32 &&
        machine_mode != ZYDIS_MACHINE_MODE_LEGACY_32)
    {
        return FALSE;
    }

    if ((PVOID)(ULONG_PTR)(vcpu->vmexit_rip & ~0xFFFULL) != hook->TargetPageBase ||
        (PVOID)(ULONG_PTR)(guest_linear & ~0xFFFULL) != hook->TargetPageBase)
    {
        return FALSE;
    }

    rip_offset = (UINT16)(vcpu->vmexit_rip & 0xFFF);
    gla_offset = (UINT16)(guest_linear & 0xFFF);

    if ((SIZE_T)rip_offset + sizeof(bytes) > PAGE_SIZE)
        return FALSE;

    RtlCopyMemory(bytes, (PUCHAR)hook->FakeVa + rip_offset, sizeof(bytes));

    for (UINT32 i = 0; i < hook->FastRuleCount && i < EPT_HOOK_MAX_FAST_RULES; ++i)
    {
        PEPT_HOOK_FAST_RULE rule = &hook->FastRules[i];

        if (rule->Type == EptHookFastRuleNone || rule->OpcodeLength == 0)
            continue;

        if (rule->RipOffset != rip_offset)
            continue;

        if (gla_offset < rule->GlaOffsetStart || gla_offset > rule->GlaOffsetEnd)
            continue;

        if (RtlCompareMemory(bytes, rule->Opcode, rule->OpcodeLength) != rule->OpcodeLength)
            continue;

        switch ((EPT_HOOK_FAST_RULE_TYPE)rule->Type)
        {
        case EptHookFastRuleLookupMovzx:
        case EptHookFastRuleLookupMovsx:
        case EptHookFastRuleLookupMov:
        {
            UINT64 raw_value = 0;
            UINT64 result_value = 0;
            ZydisRegister dst_reg = vmexit_get_32bit_gpr_by_index(rule->DestReg);
            SIZE_T target_offset = (SIZE_T)gla_offset;

            if (dst_reg == ZYDIS_REGISTER_NONE ||
                rule->DataSize == 0 ||
                rule->DataSize > sizeof(raw_value))
            {
                InterlockedIncrement64(&hook->FfShortcutFail);
                return FALSE;
            }

            if (target_offset + rule->DataSize > PAGE_SIZE)
            {
                InterlockedIncrement64(&hook->FfShortcutFail);
                return FALSE;
            }

            RtlCopyMemory(&raw_value, ((PUCHAR)hook->OriginalPageVa) + target_offset, rule->DataSize);

            if ((EPT_HOOK_FAST_RULE_TYPE)rule->Type == EptHookFastRuleLookupMovsx)
                result_value = (UINT64)vmexit_sign_extend_to_64(raw_value, (ZyanU8)(rule->DataSize * 8));
            else
                result_value = vmexit_mask_to_width(raw_value, (ZyanU8)(rule->DataSize * 8));

            result_value = vmexit_mask_to_width(result_value, 32);
            if (!vmexit_write_register_value(vcpu, machine_mode, dst_reg, result_value))
            {
                InterlockedIncrement64(&hook->FfShortcutFail);
                return FALSE;
            }

            InterlockedIncrement64(&hook->FfShortcutSuccess);
            *advance_rip = TRUE;
            return TRUE;
        }

        case EptHookFastRuleFfJmp:
        case EptHookFastRuleFfCall:
        {
            UINT32 target = 0;
            SIZE_T target_offset = (SIZE_T)gla_offset;

            if (target_offset + sizeof(target) > PAGE_SIZE)
            {
                InterlockedIncrement64(&hook->FfShortcutFail);
                return FALSE;
            }

            RtlCopyMemory(&target, ((PUCHAR)hook->OriginalPageVa) + target_offset, sizeof(target));

            if ((EPT_HOOK_FAST_RULE_TYPE)rule->Type == EptHookFastRuleFfCall)
            {
                UINT64 esp = 0;
                UINT32 new_esp = 0;
                UINT64 stack_linear = 0;
                UINT32 return_address = (UINT32)(vcpu->vmexit_rip + rule->InsnLength);

                if (!vmexit_read_register_value(vcpu, machine_mode, ZYDIS_REGISTER_ESP, &esp))
                {
                    InterlockedIncrement64(&hook->FfShortcutFail);
                    return FALSE;
                }

                new_esp = (UINT32)((UINT32)esp - sizeof(UINT32));
                stack_linear = vmexit_get_segment_base(ZYDIS_REGISTER_SS) + new_esp;

                if (!vmexit_copy_guest_linear(guest_cr3, stack_linear, &return_address, sizeof(return_address), TRUE))
                {
                    InterlockedIncrement64(&hook->FfShortcutFail);
                    return FALSE;
                }

                if (!vmexit_write_register_value(vcpu, machine_mode, ZYDIS_REGISTER_ESP, new_esp))
                {
                    InterlockedIncrement64(&hook->FfShortcutFail);
                    return FALSE;
                }
            }

            __vmx_vmwrite(VMCS_GUEST_RIP, target);
            vcpu->vmexit_rip = target;
            InterlockedIncrement64(&hook->FfShortcutSuccess);
            *advance_rip = FALSE;
            return TRUE;
        }

        default:
            break;
        }
    }

    UNREFERENCED_PARAMETER(stack_width);
    return FALSE;
}

static BOOLEAN
vmexit_try_emulate_exact_same_page_lookup_fallback_32(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_phys,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid,
    _Out_ BOOLEAN *advance_rip)
{
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    SIZE_T rip_offset;
    UCHAR bytes[8] = { 0 };

    UNREFERENCED_PARAMETER(guest_cr3);
    UNREFERENCED_PARAMETER(guest_phys);

    if (!vcpu || !hook || !advance_rip)
        return FALSE;

    vmexit_get_zydis_mode(&machine_mode, &stack_width);
    if (machine_mode != ZYDIS_MACHINE_MODE_LONG_COMPAT_32 &&
        machine_mode != ZYDIS_MACHINE_MODE_LEGACY_32)
    {
        return FALSE;
    }

    if ((PVOID)(ULONG_PTR)(vcpu->vmexit_rip & ~0xFFFULL) != hook->TargetPageBase)
        return FALSE;

    rip_offset = (SIZE_T)(vcpu->vmexit_rip & 0xFFF);
    if (rip_offset + sizeof(bytes) > PAGE_SIZE)
        return FALSE;

    //
    // Read instruction bytes from FakeVa (contains original + patches).
    //
    RtlCopyMemory(bytes, (PUCHAR)hook->FakeVa + rip_offset, sizeof(bytes));

    //
    // Warcraft-style dispatcher shortcut — register-based address computation:
    //
    //   0x22D : 0F B6 80 xx xx xx xx   movzx eax, byte ptr [eax + disp32]
    //   0x234 : FF 24 85 xx xx xx xx   jmp   dword ptr [eax*4 + disp32]
    //
    // Instead of trusting guest_phys or hardcoding GLA offset ranges, we
    // extract disp32 from the instruction bytes and compute the effective
    // address from the current guest register value.  This handles all
    // possible EAX values and does not depend on VMCS guest linear address.
    //

    // --- movzx eax, byte ptr [eax + disp32]  (7 bytes: 0F B6 80 disp32) ---
    if (rip_offset == 0x22D &&
        bytes[0] == 0x0F &&
        bytes[1] == 0xB6 &&
        bytes[2] == 0x80)
    {
        UINT32 disp32;
        UINT64 eax_value = 0;
        UINT32 mem_addr;
        UCHAR value = 0;
        SIZE_T target_offset = 0;

        disp32 = vmexit_read_u32le(&bytes[3]);

        if (!vmexit_read_register_value(vcpu, machine_mode, ZYDIS_REGISTER_EAX, &eax_value))
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }

        mem_addr = (UINT32)((UINT32)eax_value + disp32);

        if (!guest_linear_valid ||
            (UINT32)guest_linear != mem_addr ||
            (PVOID)(ULONG_PTR)(guest_linear & ~0xFFFULL) != hook->TargetPageBase)
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }

        target_offset = (SIZE_T)(guest_linear & 0xFFF);
        value = *(((PUCHAR)hook->OriginalPageVa) + target_offset);

        if (!vmexit_write_register_value(vcpu, machine_mode, ZYDIS_REGISTER_EAX, (UINT64)value))
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }

        InterlockedIncrement64(&hook->FfShortcutSuccess);
        *advance_rip = TRUE;
        UNREFERENCED_PARAMETER(stack_width);
        return TRUE;
    }

    // --- jmp dword ptr [eax*4 + disp32]  (7 bytes: FF 24 85 disp32) ---
    if (rip_offset == 0x234 &&
        bytes[0] == 0xFF &&
        bytes[1] == 0x24 &&
        bytes[2] == 0x85)
    {
        UINT32 disp32;
        UINT64 eax_value = 0;
        UINT32 table_addr;
        UINT32 target = 0;
        SIZE_T target_offset = 0;

        disp32 = vmexit_read_u32le(&bytes[3]);

        if (!vmexit_read_register_value(vcpu, machine_mode, ZYDIS_REGISTER_EAX, &eax_value))
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }

        table_addr = (UINT32)((UINT32)eax_value * 4 + disp32);

        if (!guest_linear_valid ||
            (UINT32)guest_linear != table_addr ||
            (PVOID)(ULONG_PTR)(guest_linear & ~0xFFFULL) != hook->TargetPageBase)
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }

        target_offset = (SIZE_T)(guest_linear & 0xFFF);
        if (target_offset + sizeof(target) > PAGE_SIZE)
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }

        RtlCopyMemory(&target, ((PUCHAR)hook->OriginalPageVa) + target_offset, sizeof(target));

        __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)target);
        vcpu->vmexit_rip = (UINT64)target;
        InterlockedIncrement64(&hook->FfShortcutSuccess);
        *advance_rip = FALSE;
        UNREFERENCED_PARAMETER(stack_width);
        return TRUE;
    }

    UNREFERENCED_PARAMETER(stack_width);
    return FALSE;
}

static BOOLEAN
vmexit_try_emulate_known_same_page_lookup_hotspot_32(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid,
    _Out_ BOOLEAN *advance_rip)
{
    UCHAR bytes[16] = { 0 };
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    SIZE_T rip_offset;
    SIZE_T gla_offset;
    UINT32 disp32 = 0;

    if (!vcpu || !hook || !advance_rip || !guest_linear_valid)
        return FALSE;

    vmexit_get_zydis_mode(&machine_mode, &stack_width);
    if (machine_mode != ZYDIS_MACHINE_MODE_LONG_COMPAT_32 &&
        machine_mode != ZYDIS_MACHINE_MODE_LEGACY_32)
    {
        return FALSE;
    }

    if ((PVOID)(ULONG_PTR)(vcpu->vmexit_rip & ~0xFFFULL) != hook->TargetPageBase ||
        (PVOID)(ULONG_PTR)(guest_linear & ~0xFFFULL) != hook->TargetPageBase)
    {
        return FALSE;
    }

    rip_offset = (SIZE_T)(vcpu->vmexit_rip & 0xFFF);
    gla_offset = (SIZE_T)(guest_linear & 0xFFF);
    if (rip_offset + sizeof(bytes) > PAGE_SIZE)
        return FALSE;

    RtlCopyMemory(bytes, (PUCHAR)hook->FakeVa + rip_offset, sizeof(bytes));

    //
    // Known Warcraft-style dispatcher:
    //   movzx eax, byte ptr [eax+<same-page lookup table>]
    //   jmp   dword ptr [eax*4+<same-page jump table>]
    //
    // Keep this narrow RIP-offset fallback so this page remains stable even if
    // broader heuristics fail in some future build.
    //
    if (rip_offset == 0x22D &&
        gla_offset >= 0x260 && gla_offset < 0x280 &&
        bytes[0] == 0x0F &&
        bytes[1] == 0xB6 &&
        bytes[2] == 0x80)
    {
        UCHAR value = 0;
        ZydisRegister dst_reg;

        disp32 = vmexit_read_u32le(&bytes[3]);
        if ((disp32 & ~0xFFFU) != ((UINT32)(ULONG_PTR)hook->TargetPageBase & ~0xFFFU))
            return FALSE;

        dst_reg = vmexit_get_32bit_gpr_by_index((UCHAR)((bytes[2] >> 3) & 0x7));
        if (dst_reg == ZYDIS_REGISTER_NONE)
            return FALSE;

        if (!vmexit_copy_guest_linear(guest_cr3, guest_linear, &value, sizeof(value), FALSE))
            return FALSE;

        if (!vmexit_write_register_value(vcpu, machine_mode, dst_reg, value))
            return FALSE;

        *advance_rip = TRUE;
        UNREFERENCED_PARAMETER(stack_width);
        return TRUE;
    }

    if (rip_offset == 0x234 &&
        gla_offset >= 0x258 && gla_offset < 0x280 &&
        bytes[0] == 0xFF &&
        bytes[1] == 0x24 &&
        bytes[2] == 0x85)
    {
        UINT32 target = 0;

        disp32 = vmexit_read_u32le(&bytes[3]);
        if ((disp32 & ~0xFFFU) != ((UINT32)(ULONG_PTR)hook->TargetPageBase & ~0xFFFU))
            return FALSE;

        if (!vmexit_copy_guest_linear(guest_cr3, guest_linear, &target, sizeof(target), FALSE))
            return FALSE;

        __vmx_vmwrite(VMCS_GUEST_RIP, target);
        vcpu->vmexit_rip = target;
        *advance_rip = FALSE;
        UNREFERENCED_PARAMETER(stack_width);
        return TRUE;
    }

    UNREFERENCED_PARAMETER(stack_width);
    return FALSE;
}

static BOOLEAN
vmexit_try_emulate_same_page_table_read_32(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid,
    _Out_ BOOLEAN *advance_rip)
{
    UCHAR bytes[16] = { 0 };
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    SIZE_T rip_offset;
    SIZE_T pos = 0;
    SIZE_T insn_len = 0;
    UCHAR modrm = 0;
    UINT64 raw_value = 0;
    UINT64 result_value = 0;
    ZydisRegister dst_reg = ZYDIS_REGISTER_NONE;
    ZyanU8 value_bits = 0;
    BOOLEAN sign_extend = FALSE;

    if (!vcpu || !hook || !advance_rip || !guest_linear_valid)
        return FALSE;

    vmexit_get_zydis_mode(&machine_mode, &stack_width);
    if (machine_mode != ZYDIS_MACHINE_MODE_LONG_COMPAT_32 &&
        machine_mode != ZYDIS_MACHINE_MODE_LEGACY_32)
    {
        return FALSE;
    }

    if ((PVOID)(ULONG_PTR)(vcpu->vmexit_rip & ~0xFFFULL) != hook->TargetPageBase ||
        (PVOID)(ULONG_PTR)(guest_linear & ~0xFFFULL) != hook->TargetPageBase)
    {
        return FALSE;
    }

    rip_offset = (SIZE_T)(vcpu->vmexit_rip & 0xFFF);
    if (rip_offset + sizeof(bytes) > PAGE_SIZE)
        return FALSE;

    RtlCopyMemory(bytes, (PUCHAR)hook->FakeVa + rip_offset, sizeof(bytes));

    while (pos < sizeof(bytes))
    {
        UCHAR prefix = bytes[pos];

        if (prefix == 0x66 || prefix == 0x67)
            return FALSE;

        if (prefix == 0xF0 || prefix == 0xF2 || prefix == 0xF3 ||
            prefix == 0x2E || prefix == 0x36 || prefix == 0x3E ||
            prefix == 0x26 || prefix == 0x64 || prefix == 0x65)
        {
            pos++;
            continue;
        }

        break;
    }

    if (pos >= sizeof(bytes))
        return FALSE;

    if (bytes[pos] == 0x0F)
    {
        UCHAR opcode2;

        if (pos + 3 > sizeof(bytes))
            return FALSE;

        opcode2 = bytes[pos + 1];
        switch (opcode2)
        {
        case 0xB6: value_bits = 8;  sign_extend = FALSE; break; // MOVZX r32, r/m8
        case 0xB7: value_bits = 16; sign_extend = FALSE; break; // MOVZX r32, r/m16
        case 0xBE: value_bits = 8;  sign_extend = TRUE;  break; // MOVSX r32, r/m8
        case 0xBF: value_bits = 16; sign_extend = TRUE;  break; // MOVSX r32, r/m16
        default:
            return FALSE;
        }

        if (!vmexit_parse_memory_modrm_length_32(bytes, sizeof(bytes), pos + 2, &modrm, &insn_len))
            return FALSE;
    }
    else if (bytes[pos] == 0x8B)
    {
        value_bits = 32; // MOV r32, r/m32
        sign_extend = FALSE;

        if (!vmexit_parse_memory_modrm_length_32(bytes, sizeof(bytes), pos + 1, &modrm, &insn_len))
            return FALSE;
    }
    else
    {
        return FALSE;
    }

    dst_reg = vmexit_get_32bit_gpr_by_index((UCHAR)((modrm >> 3) & 0x7));
    if (dst_reg == ZYDIS_REGISTER_NONE)
        return FALSE;

    if (!vmexit_copy_guest_linear(guest_cr3, guest_linear, &raw_value, vmexit_bits_to_bytes(value_bits), FALSE))
        return FALSE;

    if (sign_extend)
        result_value = (UINT64)vmexit_sign_extend_to_64(raw_value, value_bits);
    else
        result_value = vmexit_mask_to_width(raw_value, value_bits);

    result_value = vmexit_mask_to_width(result_value, 32);
    if (!vmexit_write_register_value(vcpu, machine_mode, dst_reg, result_value))
        return FALSE;

    *advance_rip = TRUE;
    UNREFERENCED_PARAMETER(stack_width);
    UNREFERENCED_PARAMETER(insn_len);
    return TRUE;
}

/*
 * Same-page jump table shortcut.
 *
 * When EIP is on the same physical page as the hooked page, and the
 * instruction is FF /4 (jmp [mem]) or FF /2 (call [mem]) reading data
 * from that same page, we can avoid the full decode-and-recompute path.
 *
 * Strategy:
 *   1. Read instruction bytes from FakeVa (via copy_guest_instruction_bytes)
 *   2. Quick-match FF opcode + ModRM /2 or /4 + mod!=3
 *   3. Use guest_linear (from VMCS, known valid) to read the DWORD target
 *   4. If CALL: push return address onto guest stack
 *   5. Set GUEST_RIP = target, done
 *
 * This eliminates the full SIB/displacement recompute and the translated_phys
 * == guest_phys cross-check that can fail in edge cases.
 */
static BOOLEAN
vmexit_try_emulate_same_page_jmp_table(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_phys,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid,
    _Out_ BOOLEAN *advance_rip)
{
    UCHAR bytes[16] = { 0 };
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    size_t pos = 0;
    UCHAR modrm;
    UCHAR mod;
    UCHAR opcode_extension;
    UCHAR rm;
    UINT32 target = 0;
    SIZE_T rip_pfn;
    size_t insn_len;

    UNREFERENCED_PARAMETER(guest_phys);

    if (!vcpu || !hook || !advance_rip || !guest_linear_valid)
        return FALSE;

    // Only for 32-bit compat mode
    vmexit_get_zydis_mode(&machine_mode, &stack_width);
    if (machine_mode != ZYDIS_MACHINE_MODE_LONG_COMPAT_32 &&
        machine_mode != ZYDIS_MACHINE_MODE_LEGACY_32)
    {
        return FALSE;
    }

    // Check if RIP is on the same original physical page as the hook (by VA)
    if ((PVOID)(ULONG_PTR)(vcpu->vmexit_rip & ~0xFFFULL) != hook->TargetPageBase)
        return FALSE;

    // Read instruction bytes directly from the Fake page
    size_t rip_offset = (size_t)(vcpu->vmexit_rip & 0xFFF);
    if (rip_offset + sizeof(bytes) > PAGE_SIZE)
        return FALSE; // Span across pages, reject

    RtlCopyMemory(bytes, (PUCHAR)hook->FakeVa + rip_offset, sizeof(bytes));

    // Skip legacy prefixes (segment overrides, LOCK, etc.)
    // Reject 0x66 (operand size) and 0x67 (address size) for simplicity
    while (pos < sizeof(bytes))
    {
        UCHAR prefix = bytes[pos];
        if (prefix == 0x66 || prefix == 0x67)
            return FALSE;
        if (prefix == 0xF0 || prefix == 0xF2 || prefix == 0xF3 ||
            prefix == 0x2E || prefix == 0x36 || prefix == 0x3E ||
            prefix == 0x26 || prefix == 0x64 || prefix == 0x65)
        {
            pos++;
            continue;
        }
        break;
    }

    if (pos + 2 > sizeof(bytes) || bytes[pos] != 0xFF)
        return FALSE;

    modrm = bytes[pos + 1];
    mod = (UCHAR)((modrm >> 6) & 0x3);
    opcode_extension = (UCHAR)((modrm >> 3) & 0x7);
    rm = (UCHAR)(modrm & 0x7);

    // Only handle JMP /4 and CALL /2 with memory operand (mod != 3)
    if ((opcode_extension != 2 && opcode_extension != 4) || mod == 3)
        return FALSE;

    // Compute full instruction length by walking ModR/M + SIB + displacement
    pos += 2; // past FF + modrm
    if (rm == 4)
    {
        // SIB byte present
        if (pos >= sizeof(bytes))
            return FALSE;
        UCHAR sib = bytes[pos++];
        if ((sib & 0x7) == 5 && mod == 0)
        {
            pos += 4; // disp32
        }
    }
    else if (mod == 0 && rm == 5)
    {
        pos += 4; // disp32
    }

    if (mod == 1)
        pos += 1; // disp8
    else if (mod == 2)
        pos += 4; // disp32

    insn_len = pos;

    // Verify target falls on the same hooked page (by VA)
    if ((PVOID)(ULONG_PTR)(guest_linear & ~0xFFFULL) != hook->TargetPageBase)
    {
        InterlockedIncrement64(&hook->FfShortcutFail);
        return FALSE;
    }

    // Read the 4-byte target DWORD directly from the Original page
    size_t target_offset = (size_t)(guest_linear & 0xFFF);
    if (target_offset + sizeof(target) > PAGE_SIZE)
    {
        InterlockedIncrement64(&hook->FfShortcutFail);
        return FALSE;
    }

    target = *(UINT32*)((PUCHAR)hook->OriginalPageVa + target_offset);

    // For CALL /2: push return address onto guest stack
    if (opcode_extension == 2)
    {
        UINT64 esp = 0;
        UINT32 new_esp = 0;
        UINT64 stack_linear = 0;
        UINT32 return_address = (UINT32)(vcpu->vmexit_rip + insn_len);

        if (!vmexit_read_register_value(vcpu, machine_mode, ZYDIS_REGISTER_ESP, &esp))
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }

        new_esp = (UINT32)((UINT32)esp - sizeof(UINT32));
        stack_linear = vmexit_get_segment_base(ZYDIS_REGISTER_SS) + new_esp;

        if (!vmexit_copy_guest_linear(guest_cr3, stack_linear, &return_address, sizeof(return_address), TRUE))
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }

        if (!vmexit_write_register_value(vcpu, machine_mode, ZYDIS_REGISTER_ESP, new_esp))
        {
            InterlockedIncrement64(&hook->FfShortcutFail);
            return FALSE;
        }
    }

    __vmx_vmwrite(VMCS_GUEST_RIP, target);
    vcpu->vmexit_rip = target;
    *advance_rip = FALSE;

    InterlockedIncrement64(&hook->FfShortcutSuccess);
    UNREFERENCED_PARAMETER(stack_width);
    return TRUE;
}

static BOOLEAN
vmexit_try_emulate_ff_memory_operation(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _In_ UINT64 guest_cr3,
    _In_ const ZydisDecodedInstruction *instruction,
    _In_reads_(ZYDIS_MAX_OPERAND_COUNT) const ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT],
    _In_ const ZydisDecodedOperand *mem_op,
    _In_ UINT64 mem_linear,
    _In_ ZyanU8 mem_bytes,
    _Out_ BOOLEAN *advance_rip)
{
    UINT64 target = 0;
    ZyanU8 opcode_extension;

    if (!vcpu || !instruction || !operands || !mem_op || !advance_rip)
        return FALSE;

    UNREFERENCED_PARAMETER(operands);

    if (instruction->opcode != 0xFF ||
        !(instruction->attributes & ZYDIS_ATTRIB_HAS_MODRM) ||
        instruction->raw.modrm.mod == 3)
    {
        return FALSE;
    }

    if (!vmexit_is_32bit_guest_mode(instruction) ||
        instruction->address_width != 32 ||
        instruction->operand_width != 32 ||
        mem_bytes != sizeof(UINT32) ||
        mem_op->size != 32)
    {
        return FALSE;
    }

    opcode_extension = instruction->raw.modrm.reg;

    switch (opcode_extension)
    {
    case 2: // CALL r/m
    case 4: // JMP r/m
    {
        if (!vmexit_copy_guest_linear(guest_cr3, mem_linear, &target, mem_bytes, FALSE))
            return FALSE;

        target = vmexit_mask_to_width(target, (ZyanU8)(mem_bytes * 8));
        if (vmexit_is_32bit_guest_mode(instruction))
            target = (UINT32)target;

        if (opcode_extension == 2)
        {
            UINT64 return_address = vcpu->vmexit_rip + instruction->length;
            ZyanU8 push_bytes = vmexit_bits_to_bytes((ZyanU16)instruction->operand_width);

            if (!push_bytes)
                push_bytes = mem_bytes;

            return_address = vmexit_mask_to_width(return_address, (ZyanU8)(push_bytes * 8));
            if (!vmexit_push_value_to_guest_stack(vcpu, guest_cr3, instruction, return_address, push_bytes))
                return FALSE;
        }

        __vmx_vmwrite(VMCS_GUEST_RIP, target);
        vcpu->vmexit_rip = target;
        *advance_rip = FALSE;
        return TRUE;
    }

    default:
        return FALSE;
    }
}

static BOOLEAN
vmexit_try_emulate_ept_data_access(
    _Inout_ VIRTUAL_MACHINE_STATE *vcpu,
    _Inout_ PEPT_HOOK_STATE hook,
    _In_ UINT64 guest_cr3,
    _In_ UINT64 guest_phys,
    _In_ UINT64 guest_linear,
    _In_ BOOLEAN guest_linear_valid,
    _Out_ BOOLEAN *advance_rip)
{
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    const ZydisDecodedOperand *mem_op = NULL;
    UINT64 mem_linear = 0;
    UINT64 translated_phys = 0;
    ZyanU8 mem_bytes = 0;
    BOOLEAN same_page_linear_shortcut = FALSE;

    *advance_rip = TRUE;
    RtlZeroMemory(&instruction, sizeof(instruction));
    RtlZeroMemory(operands, sizeof(operands));

    if (vmexit_try_emulate_exact_same_page_lookup_fallback_32(
            vcpu,
            hook,
            guest_cr3,
            guest_phys,
            guest_linear,
            guest_linear_valid,
            advance_rip))
    {
        return TRUE;
    }

    // Try the same-page jump-table shortcut first (uses guest_linear directly)
    if (vmexit_try_emulate_same_page_jmp_table(
            vcpu,
            hook,
            guest_cr3,
            guest_phys,
            guest_linear,
            guest_linear_valid,
            advance_rip))
    {
        return TRUE;
    }

    if (vmexit_try_emulate_ff_raw_32(
            vcpu,
            hook,
            guest_cr3,
            guest_phys,
            guest_linear,
            guest_linear_valid,
            advance_rip))
    {
        return TRUE;
    }

    if (vmexit_try_emulate_pre_scanned_fast_rule_32(
            vcpu,
            hook,
            guest_cr3,
            guest_linear,
            guest_linear_valid,
            advance_rip))
    {
        return TRUE;
    }

    if (vmexit_try_emulate_known_same_page_lookup_hotspot_32(
            vcpu,
            hook,
            guest_cr3,
            guest_linear,
            guest_linear_valid,
            advance_rip))
    {
        return TRUE;
    }

    if (vmexit_try_emulate_same_page_table_read_32(
            vcpu,
            hook,
            guest_cr3,
            guest_linear,
            guest_linear_valid,
            advance_rip))
    {
        return TRUE;
    }

    if (!vmexit_decode_instruction(vcpu, guest_cr3, &instruction, operands))
        return FALSE;

    for (ZyanU8 i = 0; i < instruction.operand_count_visible; i++)
    {
        if (operands[i].type != ZYDIS_OPERAND_TYPE_MEMORY)
            continue;

        if (mem_op)
            return FALSE;

        mem_op = &operands[i];
    }

    if (!mem_op || mem_op->size == 0 || mem_op->size > 64)
        return FALSE;

    mem_bytes = vmexit_bits_to_bytes(mem_op->size);
    if (mem_bytes == 0 || mem_bytes > sizeof(UINT64))
        return FALSE;

    if (hook &&
        guest_linear_valid &&
        (PVOID)(ULONG_PTR)(vcpu->vmexit_rip & ~0xFFFULL) == hook->TargetPageBase &&
        (PVOID)(ULONG_PTR)(guest_linear & ~0xFFFULL) == hook->TargetPageBase)
    {
        mem_linear = guest_linear;
        same_page_linear_shortcut = TRUE;
    }
    else
    {
        if (!vmexit_calculate_linear_address(vcpu, instruction.machine_mode, &instruction, mem_op, vcpu->vmexit_rip, &mem_linear))
            return FALSE;

        if (!vmexit_translate_guest_linear(guest_cr3, mem_linear, &translated_phys))
            return FALSE;

        if ((translated_phys / PAGE_SIZE) != (guest_phys / PAGE_SIZE))
            return FALSE;

        if (guest_linear_valid && mem_linear != guest_linear)
            return FALSE;
    }

    if (vmexit_try_emulate_ff_memory_operation(
            vcpu,
            guest_cr3,
            &instruction,
            operands,
            mem_op,
            mem_linear,
            mem_bytes,
            advance_rip))
    {
        return TRUE;
    }

    UNREFERENCED_PARAMETER(same_page_linear_shortcut);

    switch (instruction.mnemonic)
    {
    case ZYDIS_MNEMONIC_MOV:
    {
        const ZydisDecodedOperand *dst = &operands[0];
        const ZydisDecodedOperand *src = &operands[1];
        UINT64 value = 0;

        if (instruction.operand_count_visible < 2)
            return FALSE;

        if (dst->type == ZYDIS_OPERAND_TYPE_REGISTER && src->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (!vmexit_read_memory_operand(guest_cr3, mem_linear, src, &value))
                return FALSE;

            value = vmexit_mask_to_width(value, (ZyanU8)src->size);
            return vmexit_write_register_value(vcpu, instruction.machine_mode, dst->reg.value, value);
        }

        if (dst->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (src->type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                if (!vmexit_read_register_value(vcpu, instruction.machine_mode, src->reg.value, &value))
                    return FALSE;
            }
            else if (src->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (dst->size == 64 && src->size == 32)
                    value = (UINT64)vmexit_sign_extend_to_64(src->imm.value.u, (ZyanU8)src->size);
                else if (src->imm.is_signed)
                    value = (UINT64)vmexit_sign_extend_to_64(src->imm.value.u, (ZyanU8)src->size);
                else
                    value = src->imm.value.u;
            }
            else
            {
                return FALSE;
            }

            value = vmexit_mask_to_width(value, (ZyanU8)dst->size);
            if (!vmexit_write_memory_operand(guest_cr3, mem_linear, dst, value))
                return FALSE;

            vmexit_sync_fake_page(hook);
            return TRUE;
        }

        return FALSE;
    }

    case ZYDIS_MNEMONIC_MOVZX:
    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD:
    {
        const ZydisDecodedOperand *dst = &operands[0];
        const ZydisDecodedOperand *src = &operands[1];
        UINT64 value = 0;

        if (instruction.operand_count_visible < 2 ||
            dst->type != ZYDIS_OPERAND_TYPE_REGISTER ||
            src->type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            return FALSE;
        }

        if (!vmexit_read_memory_operand(guest_cr3, mem_linear, src, &value))
            return FALSE;

        if (instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX)
            value = vmexit_mask_to_width(value, (ZyanU8)src->size);
        else
            value = (UINT64)vmexit_sign_extend_to_64(value, (ZyanU8)src->size);

        return vmexit_write_register_value(vcpu, instruction.machine_mode, dst->reg.value, value);
    }

    case ZYDIS_MNEMONIC_CMP:
    case ZYDIS_MNEMONIC_TEST:
    {
        const ZydisDecodedOperand *lhs = NULL;
        const ZydisDecodedOperand *rhs = NULL;
        UINT64 lhs_value = 0;
        UINT64 rhs_value = 0;

        if (instruction.operand_count_visible < 2)
            return FALSE;

        lhs = &operands[0];
        rhs = &operands[1];

        if (lhs->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (!vmexit_read_memory_operand(guest_cr3, mem_linear, lhs, &lhs_value))
                return FALSE;
            lhs_value = vmexit_mask_to_width(lhs_value, (ZyanU8)lhs->size);
        }
        else if (lhs->type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (!vmexit_read_register_value(vcpu, instruction.machine_mode, lhs->reg.value, &lhs_value))
                return FALSE;
            lhs_value = vmexit_mask_to_width(lhs_value, (ZyanU8)lhs->size);
        }
        else
        {
            return FALSE;
        }

        if (rhs->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (!vmexit_read_memory_operand(guest_cr3, mem_linear, rhs, &rhs_value))
                return FALSE;
            rhs_value = vmexit_mask_to_width(rhs_value, (ZyanU8)rhs->size);
        }
        else if (rhs->type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (!vmexit_read_register_value(vcpu, instruction.machine_mode, rhs->reg.value, &rhs_value))
                return FALSE;
            rhs_value = vmexit_mask_to_width(rhs_value, (ZyanU8)rhs->size);
        }
        else if (rhs->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            if (rhs->imm.is_signed)
                rhs_value = (UINT64)vmexit_sign_extend_to_64(rhs->imm.value.u, (ZyanU8)rhs->size);
            else
                rhs_value = rhs->imm.value.u;

            rhs_value = vmexit_mask_to_width(rhs_value, (ZyanU8)lhs->size);
        }
        else
        {
            return FALSE;
        }

        if (instruction.mnemonic == ZYDIS_MNEMONIC_TEST)
            vmexit_write_test_flags(lhs_value, rhs_value, (ZyanU8)lhs->size);
        else
            vmexit_write_cmp_flags(lhs_value, rhs_value, (ZyanU8)lhs->size);

        return TRUE;
    }

    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_AND:
    case ZYDIS_MNEMONIC_OR:
    case ZYDIS_MNEMONIC_XOR:
    {
        const ZydisDecodedOperand *dst = &operands[0];
        const ZydisDecodedOperand *src = &operands[1];
        UINT64 lhs_value = 0;
        UINT64 rhs_value = 0;
        UINT64 result = 0;
        ZyanU8 width = 0;

        if (instruction.operand_count_visible < 2)
            return FALSE;

        width = (ZyanU8)dst->size;
        if (!width || width > 64)
            return FALSE;

        if (dst->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (!vmexit_read_memory_operand(guest_cr3, mem_linear, dst, &lhs_value))
                return FALSE;
        }
        else if (dst->type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (!vmexit_read_register_value(vcpu, instruction.machine_mode, dst->reg.value, &lhs_value))
                return FALSE;
        }
        else
        {
            return FALSE;
        }

        if (src->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (!vmexit_read_memory_operand(guest_cr3, mem_linear, src, &rhs_value))
                return FALSE;
        }
        else if (src->type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (!vmexit_read_register_value(vcpu, instruction.machine_mode, src->reg.value, &rhs_value))
                return FALSE;
        }
        else if (src->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            if (src->imm.is_signed)
                rhs_value = (UINT64)vmexit_sign_extend_to_64(src->imm.value.u, (ZyanU8)src->size);
            else
                rhs_value = src->imm.value.u;
        }
        else
        {
            return FALSE;
        }

        lhs_value = vmexit_mask_to_width(lhs_value, width);
        rhs_value = vmexit_mask_to_width(rhs_value, width);

        switch (instruction.mnemonic)
        {
        case ZYDIS_MNEMONIC_ADD:
            result = vmexit_mask_to_width(lhs_value + rhs_value, width);
            vmexit_write_add_flags(lhs_value, rhs_value, result, width);
            break;
        case ZYDIS_MNEMONIC_SUB:
            result = vmexit_mask_to_width(lhs_value - rhs_value, width);
            vmexit_write_cmp_flags(lhs_value, rhs_value, width);
            break;
        case ZYDIS_MNEMONIC_AND:
            result = lhs_value & rhs_value;
            vmexit_write_logic_flags(result, width);
            break;
        case ZYDIS_MNEMONIC_OR:
            result = lhs_value | rhs_value;
            vmexit_write_logic_flags(result, width);
            break;
        case ZYDIS_MNEMONIC_XOR:
            result = lhs_value ^ rhs_value;
            vmexit_write_logic_flags(result, width);
            break;
        default:
            return FALSE;
        }

        if (dst->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (!vmexit_write_memory_operand(guest_cr3, mem_linear, dst, result))
                return FALSE;

            vmexit_sync_fake_page(hook);
            return TRUE;
        }

        return vmexit_write_register_value(vcpu, instruction.machine_mode, dst->reg.value, result);
    }

    case ZYDIS_MNEMONIC_INC:
    case ZYDIS_MNEMONIC_DEC:
    {
        const ZydisDecodedOperand *dst = &operands[0];
        UINT64 lhs_value = 0;
        UINT64 result = 0;
        UINT64 old_rflags = 0;
        ZyanU8 width = 0;

        if (instruction.operand_count_visible < 1)
            return FALSE;

        width = (ZyanU8)dst->size;
        if (!width || width > 64)
            return FALSE;

        __vmx_vmread(VMCS_GUEST_RFLAGS, &old_rflags);

        if (dst->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (!vmexit_read_memory_operand(guest_cr3, mem_linear, dst, &lhs_value))
                return FALSE;
        }
        else if (dst->type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (!vmexit_read_register_value(vcpu, instruction.machine_mode, dst->reg.value, &lhs_value))
                return FALSE;
        }
        else
        {
            return FALSE;
        }

        lhs_value = vmexit_mask_to_width(lhs_value, width);
        if (instruction.mnemonic == ZYDIS_MNEMONIC_INC)
        {
            result = vmexit_mask_to_width(lhs_value + 1, width);
            vmexit_write_add_flags(lhs_value, 1, result, width);
        }
        else
        {
            result = vmexit_mask_to_width(lhs_value - 1, width);
            vmexit_write_cmp_flags(lhs_value, 1, width);
        }

        vmexit_restore_carry_flag(old_rflags);

        if (dst->type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (!vmexit_write_memory_operand(guest_cr3, mem_linear, dst, result))
                return FALSE;

            vmexit_sync_fake_page(hook);
            return TRUE;
        }

        return vmexit_write_register_value(vcpu, instruction.machine_mode, dst->reg.value, result);
    }

    case ZYDIS_MNEMONIC_CALL:
    case ZYDIS_MNEMONIC_JMP:
    {
        const ZydisDecodedOperand *target_op = &operands[0];
        UINT64 target = 0;

        if (instruction.operand_count_visible < 1 ||
            target_op->type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            return FALSE;
        }

        if (!vmexit_read_memory_operand(guest_cr3, mem_linear, target_op, &target))
            return FALSE;

        target = vmexit_mask_to_width(target, (ZyanU8)target_op->size);

        if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
        {
            UINT64 return_address = vcpu->vmexit_rip + instruction.length;
            ZyanU8 push_bytes = vmexit_bits_to_bytes((ZyanU16)instruction.operand_width);

            if (!push_bytes)
                push_bytes = mem_bytes;

            return_address = vmexit_mask_to_width(return_address, (ZyanU8)(push_bytes * 8));
            if (!vmexit_push_value_to_guest_stack(vcpu, guest_cr3, &instruction, return_address, push_bytes))
                return FALSE;
        }

        __vmx_vmwrite(VMCS_GUEST_RIP, target);
        vcpu->vmexit_rip = target;
        *advance_rip = FALSE;
        return TRUE;
    }

    case ZYDIS_MNEMONIC_PUSH:
    {
        const ZydisDecodedOperand *src = &operands[0];
        UINT64 value = 0;
        ZyanU8 push_bytes = 0;

        if (instruction.operand_count_visible < 1 ||
            src->type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            return FALSE;
        }

        if (!vmexit_read_memory_operand(guest_cr3, mem_linear, src, &value))
            return FALSE;

        push_bytes = vmexit_bits_to_bytes((ZyanU16)instruction.operand_width);
        if (!push_bytes)
            push_bytes = mem_bytes;

        value = vmexit_mask_to_width(value, (ZyanU8)(push_bytes * 8));
        return vmexit_push_value_to_guest_stack(vcpu, guest_cr3, &instruction, value, push_bytes);
    }

    default:
        break;
    }

    if (vmexit_is_cmov_mnemonic(instruction.mnemonic))
    {
        const ZydisDecodedOperand *dst = &operands[0];
        const ZydisDecodedOperand *src = &operands[1];
        UINT64 value = 0;

        if (instruction.operand_count_visible < 2 ||
            dst->type != ZYDIS_OPERAND_TYPE_REGISTER ||
            src->type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            return FALSE;
        }

        if (!vmexit_evaluate_condition(instruction.mnemonic))
            return TRUE;

        if (!vmexit_read_memory_operand(guest_cr3, mem_linear, src, &value))
            return FALSE;

        return vmexit_write_register_value(vcpu, instruction.machine_mode, dst->reg.value, value);
    }

    return FALSE;
}

VOID
vmexit_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 guest_phys = 0;
    UINT64 guest_cr3 = 0;
    UINT64 guest_linear = 0;
    PVOID  guest_page_base = NULL;
    BOOLEAN guest_linear_valid = FALSE;

    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &guest_phys);
    __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);

    VMX_EXIT_QUALIFICATION_EPT_VIOLATION qual;
    qual.AsUInt = vcpu->exit_qual;

    if (qual.ValidGuestLinearAddress)
    {
        __vmx_vmread(VMCS_GUEST_LINEAR_ADDRESS, &guest_linear);
        guest_page_base = PAGE_ALIGN((PVOID)(ULONG_PTR)guest_linear);
        guest_linear_valid = TRUE;
    }

    guest_cr3 &= ~0xFFFULL;
    SIZE_T fault_pfn = guest_phys / PAGE_SIZE;

    PEPT_HOOK_STATE hook = vmexit_find_hook_for_pfn(fault_pfn);
    BOOLEAN hook_matches_context = vmexit_hook_matches_context(hook, guest_cr3, guest_page_base);

    if (hook)
    {
        BOOLEAN emulate_advance_rip = TRUE;
        BOOLEAN guest_user_mode = vmexit_guest_is_user_mode();

        vmexit_record_hook_violation(
            hook,
            &qual,
            hook_matches_context,
            vcpu->vmexit_rip,
            guest_phys,
            guest_linear,
            guest_linear_valid);

        if (guest_user_mode &&
            hook_matches_context &&
            (qual.ReadAccess || qual.WriteAccess) &&
            vmexit_try_emulate_ept_data_access(
                vcpu,
                hook,
                guest_cr3,
                guest_phys,
                guest_linear,
                guest_linear_valid,
                &emulate_advance_rip))
        {
            InterlockedIncrement64(&hook->EmulationSuccessCount);
            vcpu->advance_rip = emulate_advance_rip;
            return;
        }
        else if (guest_user_mode &&
                 hook_matches_context &&
                 (qual.ReadAccess || qual.WriteAccess))
        {
            InterlockedIncrement64(&hook->EmulationFailureCount);
        }

        PEPT_PML1_ENTRY pml1 = ept_get_pml1(vcpu->ept_page_table, hook->OriginalPfn * PAGE_SIZE);
        if (pml1)
        {
            EPT_PML1_ENTRY new_entry;
            size_t cpu_controls = 0;
            new_entry.AsUInt = pml1->AsUInt;

            if (!hook->Enabled)
            {
                new_entry.ReadAccess      = 1;
                new_entry.WriteAccess     = 1;
                new_entry.ExecuteAccess   = 1;
                new_entry.PageFrameNumber = hook->OriginalPfn;
            }
            else if (!hook_matches_context)
            {
                new_entry.ReadAccess      = 1;
                new_entry.WriteAccess     = 1;
                new_entry.ExecuteAccess   = 1;
                new_entry.PageFrameNumber = hook->OriginalPfn;

                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &cpu_controls);
                cpu_controls |= (size_t)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, cpu_controls);

                vcpu->mtf_hook_state = hook;
                vcpu->mtf_write_occurred = (BOOLEAN)qual.WriteAccess;
            }
            else if (!guest_user_mode &&
                     qual.ReadAccess &&
                     !qual.WriteAccess)
            {
                // External tools often read target pages through guest kernel copy paths.
                // Restoring fake+MTF in the middle of that kernel read is unstable and can
                // fault repeatedly. Expose the original page without execute on this core;
                // the next execute access will fault and switch the core back to fake.
                new_entry.ReadAccess      = 1;
                new_entry.WriteAccess     = 1;
                new_entry.ExecuteAccess   = 0;
                new_entry.PageFrameNumber = hook->OriginalPfn;
            }
            else if (qual.ReadAccess || qual.WriteAccess)
            {
                // Guest is trying to read/write the execute-only page.
                // Swap back to original PFN with Read/Write access (Execute disabled).
                new_entry.ReadAccess      = 1;
                new_entry.WriteAccess     = 1;
                new_entry.ExecuteAccess   = 0;
                new_entry.PageFrameNumber = hook->OriginalPfn;

                // Set MTF to catch the instruction after it executes, so we can restore the hook.
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &cpu_controls);
                cpu_controls |= (size_t)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, cpu_controls);

                vcpu->mtf_hook_state = hook;
                vcpu->mtf_write_occurred = (BOOLEAN)qual.WriteAccess;
            }
            else if (qual.ExecuteAccess)
            {
                // Guest is trying to execute the read/write page.
                // Swap to fake PFN with Execute-only access.
                new_entry.ReadAccess      = 0;
                new_entry.WriteAccess     = 0;
                new_entry.ExecuteAccess   = 1;
                new_entry.PageFrameNumber = hook->FakePfn;
            }

            // Atomically update the EPT entry to prevent tearing
            InterlockedExchange64((volatile LONG64 *)&pml1->AsUInt, new_entry.AsUInt);

            // Flush TLB for this specific core. (Since each core handles its own faults)
            ept_invept_single(vcpu->ept_pointer);

            vcpu->advance_rip = FALSE;
            return;
        }
    }

    // Unhandled EPT violation (should not happen in identity map unless unmapped)
    vmexit_inject_gp();
    vcpu->advance_rip = FALSE;
}

VOID
vmexit_handle_vmcall(VIRTUAL_MACHINE_STATE * vcpu)
{
    PGUEST_REGS regs = vcpu->regs;

    //
    // reject VMCALL from ring 3 — only kernel callers allowed
    //
    {
        size_t guest_cs_ar = 0;
        __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &guest_cs_ar);
        if (((guest_cs_ar >> 5) & 3) != 0)
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
    }

    if (regs->r10 != 0x48564653ULL ||       // 'HVFS'
        regs->r11 != 0x564d43414c4cULL ||   // 'VMCALL'
        regs->r12 != 0x4e4f485950455256ULL)  // 'NOHYPERV'
    {
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        return;
    }

    UINT64 vmcall_num = regs->rcx;

    switch (vmcall_num)
    {
    case VMCALL_TEST:
        ept_invept_all();
        regs->rax = (UINT64)STATUS_SUCCESS;
        break;

    case VMCALL_VMXOFF:
    {
        UINT64 instr_len = 0;
        __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);

        vcpu->vmxoff.guest_rip = vcpu->vmexit_rip + instr_len;
        vcpu->vmxoff.guest_rsp = (UINT64)regs->rsp;

        //
        // save guest CR3 before VMXOFF — with USE_PRIVATE_HOST_CR3,
        // HOST_CR3 is a stale snapshot. Must restore guest CR3
        // immediately after __vmx_off() or kernel accesses fault.
        //
        UINT64 guest_cr3 = 0;
        __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);
        vcpu->vmxoff.guest_cr3 = guest_cr3;

        //
        // save guest GDTR before VMXOFF — after VM-exit, the CPU's
        // GDTR points to our private host GDT (host_gdt_va).
        // we must restore the original OS GDTR after __vmx_off(),
        // otherwise vmx_terminate() will free host_gdt_va while
        // the CPU's GDTR still references it → BSOD on next
        // interrupt, task switch, or segment load.
        //
        size_t guest_gdtr_base = 0;
        size_t guest_gdtr_limit = 0;
        __vmx_vmread(VMCS_GUEST_GDTR_BASE, &guest_gdtr_base);
        __vmx_vmread(VMCS_GUEST_GDTR_LIMIT, &guest_gdtr_limit);

        vcpu->vmxoff.executed = TRUE;
        vcpu->launched = FALSE;
        vcpu->vmx_active = FALSE;

        __vmx_off();
        __writecr3(guest_cr3);
        __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);

        //
        // restore OS GDTR — must happen after __vmx_off() but before
        // returning to guest code, so the CPU uses the real OS GDT
        // instead of our about-to-be-freed private copy.
        //
        asm_reload_gdtr((PVOID)guest_gdtr_base, (UINT32)guest_gdtr_limit);

        regs->rax = (UINT64)STATUS_SUCCESS;
        break;
    }

    default:
        regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
        break;
    }
}

VOID
vmexit_handle_triple_fault(VIRTUAL_MACHINE_STATE * vcpu)
{
    UNREFERENCED_PARAMETER(vcpu);
    vcpu->advance_rip = FALSE;
}

//
// MOV DR pass-through — required when MOV-DR exiting is forced on
// by must-be-1 bits. Without this, DR reads/writes are silently
// skipped (RIP advanced but DR unchanged), breaking EAC's DR checks.
//
// DR0-DR3, DR6: shared between host and guest (no VMCS save/load),
//   read/write hardware DRs directly.
// DR7: saved to VMCS_GUEST_DR7 on VM-exit, loaded on VM-entry.
//   Must use VMCS field, not __writedr(7) (which writes host DR7).
//
VOID
vmexit_handle_mov_dr(VIRTUAL_MACHINE_STATE * vcpu)
{
    PGUEST_REGS regs = vcpu->regs;
    UINT64      exit_qual = vcpu->exit_qual;

    UINT32 dr_num  = (UINT32)(exit_qual & 7);
    UINT32 dir     = (UINT32)((exit_qual >> 4) & 1);   // 0=to DR, 1=from DR
    UINT32 gpr_idx = (UINT32)((exit_qual >> 8) & 0xF);

    UINT64 * reg_ptr;
    switch (gpr_idx)
    {
    case 0:  reg_ptr = &regs->rax; break;
    case 1:  reg_ptr = &regs->rcx; break;
    case 2:  reg_ptr = &regs->rdx; break;
    case 3:  reg_ptr = &regs->rbx; break;
    case 4:  reg_ptr = &regs->rsp; break;
    case 5:  reg_ptr = &regs->rbp; break;
    case 6:  reg_ptr = &regs->rsi; break;
    case 7:  reg_ptr = &regs->rdi; break;
    case 8:  reg_ptr = &regs->r8;  break;
    case 9:  reg_ptr = &regs->r9;  break;
    case 10: reg_ptr = &regs->r10; break;
    case 11: reg_ptr = &regs->r11; break;
    case 12: reg_ptr = &regs->r12; break;
    case 13: reg_ptr = &regs->r13; break;
    case 14: reg_ptr = &regs->r14; break;
    case 15: reg_ptr = &regs->r15; break;
    default: reg_ptr = &regs->rax; break;
    }

    //
    // DR4/DR5 alias DR6/DR7 when CR4.DE=0, #UD when CR4.DE=1
    //
    if (dr_num == 4 || dr_num == 5)
    {
        UINT64 cr4 = 0;
        __vmx_vmread(VMCS_GUEST_CR4, &cr4);
        if (cr4 & (1ULL << 3))
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
        dr_num = (dr_num == 4) ? 6 : 7;
    }

    if (dir == 0)
    {
        UINT64 val = *reg_ptr;
        switch (dr_num)
        {
        case 0: vcpu->guest_dr0 = val; break;
        case 1: vcpu->guest_dr1 = val; break;
        case 2: vcpu->guest_dr2 = val; break;
        case 3: vcpu->guest_dr3 = val; break;
        case 6: vcpu->guest_dr6 = val; break;
        case 7:
            __vmx_vmwrite(VMCS_GUEST_DR7, val);
            break;
        }
    }
    else
    {
        UINT64 val = 0;
        switch (dr_num)
        {
        case 0: val = vcpu->guest_dr0; break;
        case 1: val = vcpu->guest_dr1; break;
        case 2: val = vcpu->guest_dr2; break;
        case 3: val = vcpu->guest_dr3; break;
        case 6: val = vcpu->guest_dr6; break;
        case 7:
            __vmx_vmread(VMCS_GUEST_DR7, &val);
            break;
        default: break;
        }
        *reg_ptr = val;
    }
}

BOOLEAN
vmexit_handler(_Inout_ PGUEST_REGS regs, _In_ VIRTUAL_MACHINE_STATE * vcpu)
{
    size_t  exit_raw = 0;
    UINT32  exit_reason    = 0;
    BOOLEAN result        = FALSE;

#if STEALTH_COMPENSATE_TIMING
    //
    // capture TSC as early as possible — used by TSC compensation to measure
    // handler overhead. Must be before any other work.
    //
    UINT64 exit_tsc_start = __rdtsc();
#endif

    vcpu->regs        = regs;
    vcpu->in_root     = TRUE;
    vcpu->advance_rip = TRUE;

    vcpu->guest_dr0 = __readdr(0);
    vcpu->guest_dr1 = __readdr(1);
    vcpu->guest_dr2 = __readdr(2);
    vcpu->guest_dr3 = __readdr(3);
    vcpu->guest_dr6 = __readdr(6);

    // __vmx_vmread writes size_t
    __vmx_vmread(VMCS_EXIT_REASON, &exit_raw);
    exit_reason = (UINT32)(exit_raw & 0xFFFF);
    vcpu->exit_reason = exit_reason;

    //
    // TSC compensation: if RDTSC exiting was armed for compensation and this
    // exit is NOT an RDTSC/RDTSCP, the attack pattern was broken (e.g. an
    // external interrupt fired between CPUID and RDTSC). Disarm and disable
    // RDTSC exiting to avoid trapping unrelated RDTSCs.
    //
#if STEALTH_COMPENSATE_TIMING
    if (vcpu->tsc_rdtsc_armed &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSC &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSCP)
    {
        vcpu->tsc_rdtsc_armed = FALSE;

        if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
        {
            size_t proc_ctrl = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
            proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
        }
    }
#endif

    __vmx_vmread(VMCS_GUEST_RIP, &vcpu->vmexit_rip);
    __vmx_vmread(VMCS_GUEST_RSP, &vcpu->regs->rsp);
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &vcpu->exit_qual);

    switch (exit_reason)
    {
    case VMX_EXIT_REASON_TRIPLE_FAULT:
        vmexit_handle_triple_fault(vcpu);
        break;

    //
    // VMX instructions in guest — inject #UD (bare metal behavior)
    //
    case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
    case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
    case VMX_EXIT_REASON_EXECUTE_VMPTRST:
    case VMX_EXIT_REASON_EXECUTE_VMREAD:
    case VMX_EXIT_REASON_EXECUTE_VMRESUME:
    case VMX_EXIT_REASON_EXECUTE_VMWRITE:
    case VMX_EXIT_REASON_EXECUTE_VMXOFF:
    case VMX_EXIT_REASON_EXECUTE_VMXON:
    case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
    case VMX_EXIT_REASON_EXECUTE_INVEPT:
    case VMX_EXIT_REASON_EXECUTE_INVVPID:
    case VMX_EXIT_REASON_EXECUTE_GETSEC:
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        break;

    case VMX_EXIT_REASON_EXECUTE_INVD:
        // INVD would discard dirty cache lines — use WBINVD instead
        __wbinvd();
        break;

    case VMX_EXIT_REASON_EXECUTE_INVLPG:
    {
        // flush combined (EPT+guest) TLB mapping for this linear address
        INVVPID_DESCRIPTOR desc = {0};
        desc.Vpid          = VPID_TAG;
        desc.LinearAddress = vcpu->exit_qual;

        if (g_ept->invvpid_individual_addr)
        {
            UINT8 ret = asm_invvpid(InvvpidIndividualAddress, &desc);
            if (ret != 0)
                asm_invvpid(InvvpidAllContexts, &desc);
        }
        else
        {
            asm_invvpid(InvvpidAllContexts, &desc);
        }
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDPMC:
    {
        UINT32 counter = (UINT32)(vcpu->regs->rcx & 0xFFFFFFFF);
        if (counter < 8 || (counter >= 0x40000000 && counter < 0x40000010))
        {
            UINT64 val = __readpmc(counter);
            vcpu->regs->rax = val & 0xFFFFFFFF;
            vcpu->regs->rdx = val >> 32;
        }
        else
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
        }
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDTSC:
    {
        UINT64 tsc = __rdtsc();
        size_t offset_raw = 0;
        __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &offset_raw);

#if STEALTH_COMPENSATE_TIMING
        if (vcpu->tsc_rdtsc_armed)
        {
            //
            // compensated path: return a value as if CPUID took bare-metal time.
            // compensated = cpuid_entry_tsc + bare_metal_cost + tsc_offset
            //
            //   t1 (guest's previous RDTSC) < cpuid_entry_tsc (exit happened after t1)
            //   so compensated > t1 + offset
            //   cpuid_entry_tsc + bare_metal_cost < tsc (real time is always ahead)
            //   so compensated < real TSC  (future native RDTSCs are safe)
            //
            tsc = vcpu->tsc_cpuid_entry
                + g_stealth_cpuid_cache.bare_metal_cpuid_cost
                + (UINT64)(INT64)offset_raw;

            vcpu->tsc_rdtsc_armed = FALSE;

            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
            {
                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }
        else
#endif
        {
            tsc = (UINT64)((INT64)tsc + (INT64)offset_raw);
        }

        vcpu->regs->rax = tsc & 0xFFFFFFFF;
        vcpu->regs->rdx = tsc >> 32;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_CPUID:
    {
        vmexit_handle_cpuid(vcpu);

#if STEALTH_COMPENSATE_TIMING
        //
        // arm RDTSC exiting for the next instruction. the timing attack
        // pattern is RDTSC -> CPUID -> RDTSC. By trapping the next RDTSC,
        // we can return a compensated value that hides VM-exit overhead.
        // TSC_OFFSET is never modified — zero drift.
        //
        if (g_stealth_enabled)
        {
            vcpu->tsc_cpuid_entry = exit_tsc_start;
            vcpu->tsc_rdtsc_armed = TRUE;

            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
            {
                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }
#endif
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDMSR:
        vmexit_handle_msr_read(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_WRMSR:
        vmexit_handle_msr_write(vcpu);
        break;

    case VMX_EXIT_REASON_MOV_CR:
        vmexit_handle_mov_cr(vcpu);
        break;

    case VMX_EXIT_REASON_MOV_DR:
        vmexit_handle_mov_dr(vcpu);
        break;

    case VMX_EXIT_REASON_EPT_VIOLATION:
        vmexit_handle_ept_violation(vcpu);
        break;

    case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
    {
        // Disable MTF
        size_t cpu_controls = 0;
        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &cpu_controls);
        cpu_controls &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, cpu_controls);

        // Restore execute-only access to the fake page
        if (vcpu->mtf_hook_state)
        {
            PEPT_HOOK_STATE hook = vcpu->mtf_hook_state;
            InterlockedIncrement64(&hook->MtfCount);
            if (hook->Enabled)
            {
                // SMC Synchronization Logic:
                // If the MTF was triggered by a Write access to the hook page,
                // the Original page now contains new self-modified code or data.
                // We must sync the Fake page to match, and then re-apply our Hook payload.
                if (vcpu->mtf_write_occurred)
                {
                    vmexit_sync_fake_page(hook);
                    vcpu->mtf_write_occurred = FALSE;
                }

                PEPT_PML1_ENTRY pml1 = ept_get_pml1(vcpu->ept_page_table, hook->OriginalPfn * PAGE_SIZE);
                if (pml1)
                {
                    EPT_PML1_ENTRY new_entry;
                    new_entry.AsUInt = pml1->AsUInt;
                    new_entry.ReadAccess      = 0;
                    new_entry.WriteAccess     = 0;
                    new_entry.ExecuteAccess   = 1;
                    new_entry.PageFrameNumber = hook->FakePfn;

                    InterlockedExchange64((volatile LONG64 *)&pml1->AsUInt, new_entry.AsUInt);

                    ept_invept_single(vcpu->ept_pointer);
                }
            }
            vcpu->mtf_hook_state = NULL;
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
    {
        //
        // EPT misconfiguration is a host-side fault — the EPT entry has
        // invalid configuration (reserved bits, write-only, etc).
        // the guest didn't cause this and can't handle it.
        // enter shutdown state — system will triple-fault cleanly.
        //
        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_SHUTDOWN);
        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_VMCALL:
        vmexit_handle_vmcall(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_XSETBV:
    {
        //
        // XSETBV — stealth: proper validation per Intel SDM
        //
        // Defeats:
        //   - XSETBV with high bits in ECX should #GP
        //   - XSETBV with valid ECX should NOT fault
        //   - XSETBV with invalid XCR0 value should #GP
        //
        UINT64 rcx_val   = vcpu->regs->rcx;
        UINT64 value  = (vcpu->regs->rdx << 32) | (vcpu->regs->rax & 0xFFFFFFFF);

        if (rcx_val & 0xFFFFFFFF00000000ULL)
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        //
        // check 2: only XCR0 (index 0) is valid
        //
        if ((UINT32)rcx_val != 0)
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        if (!stealth_is_xcr0_valid(value))
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        _xsetbv(0, value);
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_HLT:
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_HLT);
        break;

    case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
    {
        //
        // with ack-interrupt-on-exit, the CPU stores the acknowledged
        // vector in VMCS exit info. re-inject or defer if guest can't
        // accept it (IF=0 or STI/MOV-SS blocking).
        //
        size_t int_info_raw = 0;
        __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &int_info_raw);

        VMENTRY_INTERRUPT_INFORMATION int_info;
        int_info.AsUInt = (UINT32)int_info_raw;

        if (int_info.Valid)
        {
            UINT32 vector = int_info.Vector;

            size_t rflags_raw = 0;
            size_t intr_state = 0;
            __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags_raw);
            __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);

            BOOLEAN guest_interruptible =
                (rflags_raw & (1ULL << 9)) &&
                !(intr_state & (GUEST_INTR_STATE_BLOCKING_BY_STI |
                                GUEST_INTR_STATE_BLOCKING_BY_MOV_SS));

            if (guest_interruptible)
            {
                vmexit_inject_interrupt(vector);
            }
            else
            {
                //
                // guest can't take it now — defer and enable
                // interrupt-window exiting to inject later
                //
                vcpu->pending_ext_vector = (UINT8)vector;
                vcpu->has_pending_ext_interrupt = TRUE;

                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
    {
        size_t int_info_raw = 0;
        __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &int_info_raw);

        VMENTRY_INTERRUPT_INFORMATION int_info;
        int_info.AsUInt = (UINT32)int_info_raw;

        if (int_info.Valid)
        {
            if (int_info.InterruptionType == INTERRUPT_TYPE_NMI)
            {
                //
                // with virtual NMIs, the NMI exit sets blocking-by-NMI.
                // clear it before reinjecting — the NMI was intercepted
                // before guest delivery, and VM-entry re-sets blocking
                // when it delivers the injected NMI (SDM 26.6.1.2).
                //
                size_t intr_state = 0;
                __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);
                intr_state &= ~(size_t)GUEST_INTR_STATE_BLOCKING_BY_NMI;
                __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intr_state);
            }

            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, int_info.AsUInt);

            if (int_info.DeliverErrorCode)
            {
                size_t error_code = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, &error_code);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error_code);
            }

            if (int_info.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION)
            {
                size_t instr_len = 0;
                __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, instr_len);
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_INTERRUPT_WINDOW:
    {
        size_t proc_ctrl = 0;
        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
        proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING;
        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

        if (vcpu->has_pending_ext_interrupt)
        {
            vmexit_inject_interrupt(vcpu->pending_ext_vector);
            vcpu->has_pending_ext_interrupt = FALSE;
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_NMI_WINDOW:
    {
        size_t proc_ctrl = 0;
        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
        proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING;
        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

        if (vcpu->has_pending_nmi)
        {
            VMENTRY_INTERRUPT_INFORMATION nmi_info = {0};
            nmi_info.Vector           = EXCEPTION_VECTOR_NMI;
            nmi_info.InterruptionType = INTERRUPT_TYPE_NMI;
            nmi_info.Valid            = 1;
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, nmi_info.AsUInt);
            vcpu->has_pending_nmi = FALSE;
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_MWAIT:
        break;

    case VMX_EXIT_REASON_EXECUTE_MONITOR:
        break;

    case VMX_EXIT_REASON_EXECUTE_PAUSE:
        break;

    case VMX_EXIT_REASON_EXECUTE_RDTSCP:
    {
        unsigned int aux = 0;
        UINT64 tsc = __rdtscp(&aux);
        size_t offset_raw = 0;
        __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &offset_raw);

#if STEALTH_COMPENSATE_TIMING
        if (vcpu->tsc_rdtsc_armed)
        {
            tsc = vcpu->tsc_cpuid_entry
                + g_stealth_cpuid_cache.bare_metal_cpuid_cost
                + (UINT64)(INT64)offset_raw;

            vcpu->tsc_rdtsc_armed = FALSE;

            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
            {
                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }
        else
#endif
        {
            tsc = (UINT64)((INT64)tsc + (INT64)offset_raw);
        }

        vcpu->regs->rax = tsc & 0xFFFFFFFF;
        vcpu->regs->rdx = tsc >> 32;
        vcpu->regs->rcx = (UINT64)aux;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_WBINVD:
        __wbinvd();
        break;

    default:
        break;
    }

    //
    // re-inject IDT vectoring event if one was in progress during this VM-exit.
    // skip when vmxoff has been executed — vmread would #UD outside VMX.
    //
    if (!vcpu->vmxoff.executed)
    {
        size_t idt_vec_raw = 0;
        __vmx_vmread(VMCS_IDT_VECTORING_INFORMATION, &idt_vec_raw);

        VMENTRY_INTERRUPT_INFORMATION idt_vec;
        idt_vec.AsUInt = (UINT32)idt_vec_raw;

        if (idt_vec.Valid)
        {
            BOOLEAN reinject_idt = TRUE;

            //
            // exception combining (SDM Vol 3 Table 6-5):
            // when a hardware exception occurs during delivery of another
            // hardware exception, certain combinations produce #DF or
            // triple fault instead of serial delivery.
            //
            if (exit_reason == VMX_EXIT_REASON_EXCEPTION_OR_NMI)
            {
                size_t exit_int_raw = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &exit_int_raw);

                VMENTRY_INTERRUPT_INFORMATION exit_int;
                exit_int.AsUInt = (UINT32)exit_int_raw;

                if (exit_int.Valid &&
                    idt_vec.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION &&
                    exit_int.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION)
                {
                    if (classify_exception(idt_vec.Vector) == EXCEPTION_CLASS_DOUBLE_FAULT)
                    {
                        // #DF + any exception = triple fault
                        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
                        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_SHUTDOWN);
                        reinject_idt = FALSE;
                    }
                    else if (should_generate_df(idt_vec.Vector, exit_int.Vector))
                    {
                        // contributory+contributory, PF+contributory, PF+PF → #DF
                        vmexit_inject_df();
                        reinject_idt = FALSE;
                    }
                    // else: benign combination — reinject IDT event,
                    // exit exception regenerates during delivery
                }
            }

            if (reinject_idt)
            {
                // if the handler already queued an NMI injection, defer it —
                // IDT vectoring event takes priority
                size_t entry_info_raw = 0;
                __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, &entry_info_raw);

                VMENTRY_INTERRUPT_INFORMATION entry_info;
                entry_info.AsUInt = (UINT32)entry_info_raw;

                if (entry_info.Valid && entry_info.InterruptionType == INTERRUPT_TYPE_NMI)
                {
                    vcpu->has_pending_nmi = TRUE;

                    size_t proc_ctrl = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                    proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING;
                    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
                }

                __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, idt_vec.AsUInt);

                if (idt_vec.DeliverErrorCode)
                {
                    size_t idt_err = 0;
                    __vmx_vmread(VMCS_IDT_VECTORING_ERROR_CODE, &idt_err);
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, idt_err);
                }

                if (idt_vec.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION ||
                    idt_vec.InterruptionType == INTERRUPT_TYPE_SOFTWARE_INTERRUPT)
                {
                    size_t instr_len = 0;
                    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, instr_len);
                }
            }

            vcpu->advance_rip = FALSE;
        }
    }

    if (!vcpu->vmxoff.executed && vcpu->advance_rip)
    {
        vmexit_advance_rip(vcpu);
    }

    if (!vcpu->vmxoff.executed)
    {
        __writedr(0, vcpu->guest_dr0);
        __writedr(1, vcpu->guest_dr1);
        __writedr(2, vcpu->guest_dr2);
        __writedr(3, vcpu->guest_dr3);
        __writedr(6, vcpu->guest_dr6);
    }

    if (vcpu->vmxoff.executed)
    {
        result = TRUE;
    }

    vcpu->in_root = FALSE;
    return result;
}
