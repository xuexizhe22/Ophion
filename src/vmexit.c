/*
*   vmexit.c - vm-exit handler — dispatches exits to sub-handlers
*   this is called from assembly (asm_vmexit_handler) with:
*   rcx = pguest_regs (pushed gprs on stack)
*/
#include "hv.h"

static volatile LONG g_synthetic_msr_log_budget = 8;
static volatile LONG g_guest_idle_log_budget = 1;
static volatile LONG g_crash_msr_log_budget = 4;
static volatile LONG64 g_hv_crash_msrs[6] = {0};

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

VOID
vmexit_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 guest_phys = 0;
    UINT64 guest_cr3 = 0;
    UINT64 guest_linear = 0;
    PVOID  guest_page_base = NULL;

    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &guest_phys);
    __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);

    VMX_EXIT_QUALIFICATION_EPT_VIOLATION qual;
    qual.AsUInt = vcpu->exit_qual;

    if (qual.ValidGuestLinearAddress)
    {
        __vmx_vmread(VMCS_GUEST_LINEAR_ADDRESS, &guest_linear);
        guest_page_base = PAGE_ALIGN((PVOID)(ULONG_PTR)guest_linear);
    }

    guest_cr3 &= ~0xFFFULL;
    SIZE_T fault_pfn = guest_phys / PAGE_SIZE;

    // Search for the hooked page
    PLIST_ENTRY entry = g_ept->hooked_pages.Flink;
    PEPT_HOOK_STATE hook = NULL;
    BOOLEAN hook_matches_context = FALSE;

    while (entry != &g_ept->hooked_pages)
    {
        PEPT_HOOK_STATE current = CONTAINING_RECORD(entry, EPT_HOOK_STATE, ListEntry);
        if (current->OriginalPfn == fault_pfn || current->FakePfn == fault_pfn)
        {
            hook = current;
            hook_matches_context =
                current->Enabled &&
                (!current->TargetCr3 || current->TargetCr3 == guest_cr3) &&
                (!current->TargetPageBase || !guest_page_base || current->TargetPageBase == guest_page_base);
            break;
        }
        entry = entry->Flink;
    }

    if (hook)
    {
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

                // ====================================================================
                // TF Backoff Logic for Debugger Compatibility
                // ====================================================================
                size_t guest_rflags = 0;
                __vmx_vmread(VMCS_GUEST_RFLAGS, &guest_rflags);

                // Check if the Guest Trap Flag (TF) is set (Bit 8)
                if (guest_rflags & 0x100)
                {
                    vcpu->guest_tf_active = TRUE;
                    // Clear the TF flag temporarily to avoid conflict with MTF
                    guest_rflags &= ~0x100ULL;
                    __vmx_vmwrite(VMCS_GUEST_RFLAGS, guest_rflags);
                }
                else
                {
                    vcpu->guest_tf_active = FALSE;
                }
                // ====================================================================

                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &cpu_controls);
                cpu_controls |= (size_t)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, cpu_controls);

                vcpu->mtf_hook_state = hook;
                vcpu->mtf_write_occurred = (BOOLEAN)qual.WriteAccess;
            }
            else if (qual.ReadAccess || qual.WriteAccess)
            {
                // Safety check for Driver Cloaking (Anti-Dump):
                // If a driver cloaked itself (OriginalPfn is the Dummy Page), we DO NOT allow writes.
                // We also DO NOT copy writes to the FakePfn. The cloaked page is read-only 0x00.
                if (hook->OriginalPfn == g_ept->dummy_page_pfn && qual.WriteAccess)
                {
                    // Ignore writes to the dummy page to prevent memory corruption.
                    vmexit_inject_gp();
                    vcpu->advance_rip = FALSE;
                    return;
                }

                // Guest is trying to read/write the execute-only page.

                // === DBVM-Style Micro-Emulator Fast-Path (The Ultimate Ping-Pong Killer) ===
                // We specifically target the instruction: FF 24 85 <imm32> (jmp dword ptr [eax*4+imm32])
                // This is a 32-bit jump table read that causes massive ping-pong in war3.exe
                if (qual.ReadAccess && !qual.WriteAccess && hook->Enabled)
                {
                    UINT64 guest_rip = 0;
                    __vmx_vmread(VMCS_GUEST_RIP, &guest_rip);

                    // We only emulate if the executing instruction is also on this exact fake page
                    UINT64 page_base_va = guest_rip & ~0xFFFULL;
                    if (page_base_va == (UINT64)hook->OriginalPageVa ||
                        (hook->TargetPageBase && page_base_va == (UINT64)hook->TargetPageBase))
                    {
                        // Safely read the instruction bytes from our locked kernel mapping (FakeVa)
                        PUCHAR inst = (PUCHAR)hook->FakeVa + (guest_rip & 0xFFF);

                        // Check for JMP DWORD PTR [reg*4+imm32] (FF 24 XX)
                        if ((guest_rip & 0xFFF) <= (PAGE_SIZE - 2) && inst[0] == 0xFF && inst[1] == 0x24)
                        {
                            // We are reading from a jump table!
                            // We already know the EXACT physical address the instruction is trying to read: guest_phys
                            // We just read the 4-byte jump target from our safe kernel mapping of the Original Page
                            if ((guest_phys & 0xFFF) <= (PAGE_SIZE - 4))
                            {
                                ULONG target_rip = *(ULONG*)((PUCHAR)hook->OriginalPageVa + (guest_phys & 0xFFF));

                                // Fast-Path: We successfully emulated the memory read AND the jump!
                                // 1. Update RIP to the new jump target
                                __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)target_rip);

                                // 2. DO NOT change EPT permissions, DO NOT enable MTF!
                                // We completely bypassed the Ping-Pong!
                                vcpu->advance_rip = FALSE;
                                return;
                            }
                        }
                    }
                }

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

    // Dynamic EPT Allocation / Passthrough (DBVM-Style):
    // If we hit an unhandled EPT violation (e.g. newly loaded driver MMIO, hot-plug RAM),
    // instead of blindly injecting #GP (which causes BSODs like KMODE_EXCEPTION_NOT_HANDLED),
    // we dynamically grant R/W/X permissions to the missing page, mapping it directly.
    // This allows the Windows memory manager to dynamically allocate non-paged pools or MMIO safely.
    PEPT_PML1_ENTRY pml1 = ept_get_pml1(vcpu->ept_page_table, guest_phys);
    if (pml1)
    {
        EPT_PML1_ENTRY new_entry;
        new_entry.AsUInt = pml1->AsUInt;
        new_entry.ReadAccess    = 1;
        new_entry.WriteAccess   = 1;
        new_entry.ExecuteAccess = 1;
        new_entry.PageFrameNumber = guest_phys / PAGE_SIZE; // Crucial fix: assign correct PFN instead of leaving it 0

        InterlockedExchange64((volatile LONG64 *)&pml1->AsUInt, new_entry.AsUInt);
        ept_invept_single(vcpu->ept_pointer);
    }
    else
    {
        // If it's a 2MB large page that triggered the violation, we update the PML2 entry
        PEPT_PML2_ENTRY pml2 = ept_get_pml2(vcpu->ept_page_table, guest_phys);
        if (pml2 && pml2->LargePage)
        {
            EPT_PML2_ENTRY new_entry2;
            new_entry2.AsUInt = pml2->AsUInt;
            new_entry2.ReadAccess    = 1;
            new_entry2.WriteAccess   = 1;
            new_entry2.ExecuteAccess = 1;
            new_entry2.PageFrameNumber = guest_phys / SIZE_2_MB;

            InterlockedExchange64((volatile LONG64 *)&pml2->AsUInt, new_entry2.AsUInt);
            ept_invept_single(vcpu->ept_pointer);
        }
        else
        {
            // Absolute worst-case scenario: No page table entry exists for this physical address.
            // We pass it to the guest safely via #PF instead of #GP if possible, or just ignore.
            // Actually, we shouldn't #GP. Just let the guest handle it natively.
            // But since the hardware needs a translation, we must #PF or let it crash.
            vmexit_inject_gp();
        }
    }

    // We do not advance RIP because we want the instruction to re-execute successfully now.
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
    case VMCALL_HIDE_DRIVER_PAGE:
    {
        // Simple Driver Cloaking (Anti-Dump):
        // The driver calls this VMCALL with RDX = Virtual Address of the page to hide.
        // We set the EPT so that reads return zeros (Dummy Page), while execution stays on the real page.
        UINT64 target_va = regs->rdx;
        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)target_va);

        if (pa.QuadPart != 0 && g_ept && g_ept->dummy_page_va)
        {
            SIZE_T real_pfn = pa.QuadPart / PAGE_SIZE;

            PEPT_PML1_ENTRY pml1 = ept_get_pml1(vcpu->ept_page_table, pa.QuadPart);
            if (pml1)
            {
                EPT_PML1_ENTRY new_entry;
                new_entry.AsUInt = pml1->AsUInt;

                // Read/Write access points to the Dummy Page (all 0x00s)
                // Execute access is revoked from the Dummy Page.
                // When an execute violation occurs, we will swap to the real page.
                new_entry.ReadAccess      = 1;
                new_entry.WriteAccess     = 1;
                new_entry.ExecuteAccess   = 0;
                new_entry.PageFrameNumber = g_ept->dummy_page_pfn;

                InterlockedExchange64((volatile LONG64 *)&pml1->AsUInt, new_entry.AsUInt);

                // We expect the caller to have pre-allocated and locked the EPT_HOOK_STATE structure
                // and passed its physical address in R8, since we cannot call ExAllocatePool in VMX Root.
                // Assuming R8 contains the physical address of the pre-allocated hook struct.
                PHYSICAL_ADDRESS hook_pa;
                hook_pa.QuadPart = regs->r8;
                PEPT_HOOK_STATE hook = (PEPT_HOOK_STATE)MmGetVirtualForPhysical(hook_pa); // Only safe for resident RAM

                if (hook)
                {
                    RtlZeroMemory(hook, sizeof(EPT_HOOK_STATE));
                    hook->OriginalPfn = g_ept->dummy_page_pfn;
                    hook->FakePfn     = real_pfn;
                    hook->OriginalPageVa = g_ept->dummy_page_va;
                    hook->FakeVa      = (PVOID)target_va;
                    hook->TargetCr3   = g_system_cr3;
                    hook->Enabled     = TRUE;

                    // In VMX Root, we do not have IRQL and cannot safely use KeAcquireSpinLock.
                    // We use a raw Interlocked mechanism to build a simple lock-free append or a bare spinlock.
                    // Since this is a PoC, we do a raw spin.
                    while (InterlockedBitTestAndSet64((LONG64*)&g_ept->hook_lock, 0)) { _mm_pause(); }
                    InsertTailList(&g_ept->hooked_pages, &hook->ListEntry);
                    InterlockedAnd64((LONG64*)&g_ept->hook_lock, 0); // Release

                    DbgPrintEx(0, 0, "[hv] VMCALL Cloaked Page: VA=0x%llX, RealPFN=0x%llX\n", target_va, real_pfn);
                }

                ept_invept_all();
                regs->rax = (UINT64)STATUS_SUCCESS;
            }
            else
            {
                regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            regs->rax = (UINT64)STATUS_INVALID_PARAMETER;
        }
        break;
    }

    case VMCALL_TEST:
        ept_invept_all();
        if (vcpu->dr0_hook_enabled)
        {
            // Write the hardware breakpoint into the real guest DR0
            __writedr(0, vcpu->dr0_hook_target_rip);
            // Enable DR0 global breakpoint (bit 1), Execution breakpoint (bits 16,17=00), 1-byte length (bits 18,19=00)
            __vmx_vmwrite(VMCS_GUEST_DR7, 0x00000402ULL);
        }
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

        vcpu->vmxoff.executed = TRUE;
        vcpu->launched = FALSE;
        vcpu->vmx_active = FALSE;

        __vmx_off();
        __writecr3(guest_cr3);
        __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);

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
        case 0:
            if (!vcpu->dr0_hook_enabled) vcpu->guest_dr0 = val;
            break;
        case 1: vcpu->guest_dr1 = val; break;
        case 2: vcpu->guest_dr2 = val; break;
        case 3: vcpu->guest_dr3 = val; break;
        case 6: vcpu->guest_dr6 = val; break;
        case 7:
            if (vcpu->dr0_hook_enabled)
            {
                // Force our DR0 breakpoint to stay active (G0=1, LEN0/RW0=0000)
                UINT64 actual_dr7 = (val & ~0x000F0003ULL) | 0x00000402ULL;
                __vmx_vmwrite(VMCS_GUEST_DR7, actual_dr7);
            }
            else
            {
                __vmx_vmwrite(VMCS_GUEST_DR7, val);
            }
            break;
        }
    }
    else
    {
        UINT64 val = 0;
        switch (dr_num)
        {
        case 0: val = vcpu->dr0_hook_enabled ? 0 : vcpu->guest_dr0; break;
        case 1: val = vcpu->guest_dr1; break;
        case 2: val = vcpu->guest_dr2; break;
        case 3: val = vcpu->guest_dr3; break;
        case 6: val = vcpu->guest_dr6; break;
        case 7:
            __vmx_vmread(VMCS_GUEST_DR7, &val);
            if (vcpu->dr0_hook_enabled)
            {
                // Hide our breakpoint from the guest's read
                val &= ~0x000F0003ULL;
            }
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
            if (hook->Enabled)
            {
                // SMC Synchronization Logic:
                // If the MTF was triggered by a Write access to the hook page,
                // the Original page now contains new self-modified code or data.
                // We must sync the Fake page to match, and then re-apply our Hook payload.
                if (vcpu->mtf_write_occurred)
                {
                    // We must use the mapped and locked system virtual addresses.
                    // Directly accessing physical memory in VMX root will cause a #PF and a fatal BSOD.
                    PVOID original_page_ptr = hook->OriginalPageVa;
                    PVOID fake_page_ptr = hook->FakeVa;

                    // 1. Copy newly modified page from Original to Fake
                    RtlCopyMemory(fake_page_ptr, original_page_ptr, PAGE_SIZE);

                    // 2. Re-apply our custom hook payload so it isn't erased
                    if (hook->PatchSize > 0)
                    {
                        RtlCopyMemory(
                            (PUCHAR)fake_page_ptr + hook->PatchOffset,
                            hook->PatchBytes,
                            hook->PatchSize
                        );
                    }

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

        // ====================================================================
        // Restore Guest TF and inject #DB if necessary
        // ====================================================================
        if (vcpu->guest_tf_active)
        {
            size_t guest_rflags = 0;
            __vmx_vmread(VMCS_GUEST_RFLAGS, &guest_rflags);

            // Restore TF
            guest_rflags |= 0x100ULL;
            __vmx_vmwrite(VMCS_GUEST_RFLAGS, guest_rflags);

            // Inject a #DB exception to the Guest (Vector 1, Type: Hardware Exception)
            // Valid bit (31), Type Hardware Exception (011b), Vector 1
            UINT32 interrupt_info = 0x80000301;
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, interrupt_info);
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);

            // Need to set pending debug exceptions (BS - Single Step) to make the guest debugger happy
            // VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS bit 14 is BS (Single Step)
            size_t pending_dbg = 0;
            __vmx_vmread(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, &pending_dbg);
            pending_dbg |= (1ULL << 14);
            __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, pending_dbg);

            vcpu->guest_tf_active = FALSE;
        }
        // ====================================================================

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
            if (int_info.Vector == EXCEPTION_VECTOR_DEBUG)
            {
                UINT64 guest_rip = 0;
                UINT64 guest_cr3 = 0;
                __vmx_vmread(VMCS_GUEST_RIP, &guest_rip);
                __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);
                guest_cr3 &= ~0xFFFULL;

                if (vcpu->dr0_hook_enabled &&
                    guest_rip == vcpu->dr0_hook_target_rip &&
                    (!vcpu->dr0_hook_target_cr3 || vcpu->dr0_hook_target_cr3 == guest_cr3))
                {
                    // Acknowledge DB exception by clearing DR6 B0 so the guest OS doesn't see it
                    UINT64 guest_dr6 = 0;
                    __vmx_vmread(VMCS_GUEST_DR6, &guest_dr6);
                    guest_dr6 &= ~1ULL;
                    __vmx_vmwrite(VMCS_GUEST_DR6, guest_dr6);

                    // Suppress re-execution of the breakpoint by setting the Resume Flag (RF)
                    UINT64 rflags = 0;
                    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
                    rflags |= (1ULL << 16); // RF flag
                    __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags);

                    if (vcpu->dr0_hook_redirect_rip)
                    {
                        // Mode 2: Execution Redirect
                        __vmx_vmwrite(VMCS_GUEST_RIP, vcpu->dr0_hook_redirect_rip);
                    }
                    else
                    {
                        // Mode 1: Context Modification
                        if (vcpu->dr0_hook_modify_reg_idx != 0xFF)
                        {
                            UINT64* reg_ptr = NULL;
                            switch (vcpu->dr0_hook_modify_reg_idx) {
                                case 0: reg_ptr = &vcpu->regs->rax; break;
                                case 1: reg_ptr = &vcpu->regs->rcx; break;
                                case 2: reg_ptr = &vcpu->regs->rdx; break;
                                case 3: reg_ptr = &vcpu->regs->rbx; break;
                                case 5: reg_ptr = &vcpu->regs->rbp; break;
                                case 6: reg_ptr = &vcpu->regs->rsi; break;
                                case 7: reg_ptr = &vcpu->regs->rdi; break;
                                case 8: reg_ptr = &vcpu->regs->r8; break;
                                case 9: reg_ptr = &vcpu->regs->r9; break;
                                case 10: reg_ptr = &vcpu->regs->r10; break;
                                case 11: reg_ptr = &vcpu->regs->r11; break;
                                case 12: reg_ptr = &vcpu->regs->r12; break;
                                case 13: reg_ptr = &vcpu->regs->r13; break;
                                case 14: reg_ptr = &vcpu->regs->r14; break;
                                case 15: reg_ptr = &vcpu->regs->r15; break;
                            }
                            if (reg_ptr) {
                                *reg_ptr = vcpu->dr0_hook_modify_reg_val;
                            }
                        }
                    }

                    vcpu->advance_rip = FALSE;
                    return;
                }
            }

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
