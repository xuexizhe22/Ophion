/*
*   hv_types.h - core hypervisor type definitions — per-vcpu state, ept structures, configs
*   zero windows api dependency in vmx-root mode by design
*/
#pragma once

#include "ia32.h"

#ifndef MAXULONG64
#define MAXULONG64              ((ULONG64)~((ULONG64)0))
#endif

#define VMM_STACK_SIZE          0x8000      // 32 KB per-VCPU VMM stack
#define VMM_STACK_VCPU_OFFSET   8           // vcpu ptr stored at top-8 of stack
#define VMXON_SIZE              0x1000
#define VMCS_SIZE               0x1000
#define MAX_PROCESSORS          256
#define MAX_MTRR_RANGES         256
#define EPT_HOOK_MAX_PATCH_SIZE 16
#define EPT_HOOK_MAX_PATCHES_PER_PAGE 8
#define EPT_HOOK_HOTSPOT_COUNT  8
#define EPT_HOOK_HOTSPOT_SAMPLE_EVERY 16
#define EPT_HOOK_MAX_FAST_RULES 8

typedef struct _EPT_HOOK_PATCH_ENTRY {
    SIZE_T Offset;
    SIZE_T Size;
    UCHAR  Bytes[EPT_HOOK_MAX_PATCH_SIZE];
} EPT_HOOK_PATCH_ENTRY, *PEPT_HOOK_PATCH_ENTRY;

typedef struct _EPT_HOOK_HOTSPOT_ENTRY {
    UINT64 Rip;
    UINT64 GuestPhysical;
    UINT64 GuestLinear;
    UINT64 HitCount;
    UINT32 Flags;
    UINT32 Reserved;
} EPT_HOOK_HOTSPOT_ENTRY, *PEPT_HOOK_HOTSPOT_ENTRY;

typedef enum _EPT_HOOK_FAST_RULE_TYPE {
    EptHookFastRuleNone = 0,
    EptHookFastRuleLookupMovzx = 1,
    EptHookFastRuleLookupMovsx = 2,
    EptHookFastRuleLookupMov = 3,
    EptHookFastRuleFfJmp = 4,
    EptHookFastRuleFfCall = 5
} EPT_HOOK_FAST_RULE_TYPE;

typedef struct _EPT_HOOK_FAST_RULE {
    UINT16 RipOffset;
    UINT16 GlaOffsetStart;
    UINT16 GlaOffsetEnd;
    UINT8  Type;
    UINT8  DestReg;
    UINT8  DataSize;
    UINT8  InsnLength;
    UINT8  Opcode[4];
    UINT8  OpcodeLength;
    UINT8  Reserved[3];
} EPT_HOOK_FAST_RULE, *PEPT_HOOK_FAST_RULE;

#define HV_POOL_TAG             'nhpO'

typedef struct _GUEST_REGS {
    UINT64 rax;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rbx;
    UINT64 rsp;    // placeholder — real RSP read from VMCS
    UINT64 rbp;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;
} GUEST_REGS, *PGUEST_REGS;

typedef struct _VMX_VMXOFF_STATE {
    BOOLEAN executed;
    UINT64  guest_rip;
    UINT64  guest_rsp;
    UINT64  guest_cr3;
} VMX_VMXOFF_STATE;

typedef struct _MTRR_RANGE_DESCRIPTOR {
    UINT64  phys_base;
    UINT64  phys_end;
    UINT8   mem_type;
    BOOLEAN fixed;
} MTRR_RANGE_DESCRIPTOR;

typedef struct _VMM_EPT_PAGE_TABLE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4_ENTRY   PML4[VMM_EPT_PML4E_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML2_ENTRY   PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];
} VMM_EPT_PAGE_TABLE, *PVMM_EPT_PAGE_TABLE;

//
// dynamic split: when we split a 2MB page into 512 4KB pages
//
typedef struct _VMM_EPT_DYNAMIC_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML1_ENTRY PML1[VMM_EPT_PML1E_COUNT];
    union {
        PEPT_PML2_ENTRY   Entry;
        PEPT_PML2_POINTER Pointer;
    } u;
    LIST_ENTRY SplitList;
} VMM_EPT_DYNAMIC_SPLIT, *PVMM_EPT_DYNAMIC_SPLIT;

typedef struct _EPT_HOOK_STATE {
    LIST_ENTRY ListEntry;
    SIZE_T     OriginalPfn;
    SIZE_T     FakePfn;
    BOOLEAN    Enabled;
    volatile LONG AccessLock;
    volatile LONG HotspotLock;
    UINT64     TargetCr3;
    PVOID      TargetPageBase;
    PVOID      OriginalPageVa;
    PVOID      FakeVa;
    PEPROCESS  ProcessObject;
    PMDL       LockedMdl;
    HANDLE     ProcessId;
    UINT32     PatchCount;
    SIZE_T     PatchOffset;
    SIZE_T     PatchSize;
    UCHAR      PatchBytes[EPT_HOOK_MAX_PATCH_SIZE];
    EPT_HOOK_PATCH_ENTRY Patches[EPT_HOOK_MAX_PATCHES_PER_PAGE];
    volatile LONG64 ExecuteViolationCount;
    volatile LONG64 ReadViolationCount;
    volatile LONG64 WriteViolationCount;
    volatile LONG64 ContextMismatchCount;
    volatile LONG64 MtfCount;
    volatile LONG64 EmulationSuccessCount;
    volatile LONG64 EmulationFailureCount;
    volatile LONG64 LastViolationRip;
    volatile LONG64 LastGuestPhysical;
    volatile LONG64 LastGuestLinear;
    volatile LONG   LastViolationFlags;
    volatile LONG64 HotspotSequence;
    EPT_HOOK_HOTSPOT_ENTRY Hotspots[EPT_HOOK_HOTSPOT_COUNT];
    UINT32     FastRuleCount;
    EPT_HOOK_FAST_RULE FastRules[EPT_HOOK_MAX_FAST_RULES];

    // FF-raw-32 emulation diagnostics
    volatile LONG64 FfRawFailMode;         // failed: not 32-bit compat mode
    volatile LONG64 FfRawFailInsnRead;     // failed: instruction bytes read
    volatile LONG64 FfRawFailOpcode;       // failed: opcode/modrm/prefix check
    volatile LONG64 FfRawFailAddrCalc;     // failed: address calc / phys mismatch
    volatile LONG64 FfRawFailTargetRead;   // failed: reading target DWORD
    volatile LONG64 FfRawFailStack;        // failed: CALL stack push
    volatile LONG64 FfRawSuccess;          // general path success
    volatile LONG64 FfShortcutSuccess;     // same-page shortcut success
    volatile LONG64 FfShortcutFail;        // same-page shortcut failed
} EPT_HOOK_STATE, *PEPT_HOOK_STATE;

typedef struct _EPT_STATE {
    MTRR_RANGE_DESCRIPTOR mem_ranges[MAX_MTRR_RANGES];
    UINT32                num_ranges;
    UINT8                 default_type;
    BOOLEAN               ad_supported;
    LIST_ENTRY            hooked_pages;    // active EPT hooks
    LIST_ENTRY            dynamic_splits;  // split PML1 tables allocated on demand

    //
    // INVVPID capability bits (cached from IA32_VMX_EPT_VPID_CAP)
    //
    BOOLEAN               invvpid_supported;
    BOOLEAN               invvpid_individual_addr;
    BOOLEAN               invvpid_single_context;
    BOOLEAN               invvpid_all_contexts;
    BOOLEAN               invvpid_single_retaining_globals;
} EPT_STATE, *PEPT_STATE;

typedef struct _VIRTUAL_MACHINE_STATE {

    UINT64 vmxon_va;
    UINT64 vmxon_pa;
    UINT64 vmcs_va;
    UINT64 vmcs_pa;

    //
    // VMM stack (HOST_RSP points near top of this)
    //
    UINT64 vmm_stack;

    UINT64 msr_bitmap_va;
    UINT64 msr_bitmap_pa;
    UINT64 io_bitmap_va_a;
    UINT64 io_bitmap_pa_a;
    UINT64 io_bitmap_va_b;
    UINT64 io_bitmap_pa_b;

    PVMM_EPT_PAGE_TABLE ept_page_table;
    EPT_POINTER         ept_pointer;

    PGUEST_REGS regs;
    UINT32      core_id;
    UINT32      exit_reason;
    UINT64      exit_qual;
    UINT64      vmexit_rip;
    BOOLEAN     in_root;
    BOOLEAN     vmx_active;
    BOOLEAN     launched;
    BOOLEAN     advance_rip;

    VMX_VMXOFF_STATE vmxoff;

    //
    // stealth: per-VCPU TSC compensation state for "trap next RDTSC" approach.
    // after CPUID exit, RDTSC exiting is armed for one instruction.
    // the trapped RDTSC returns a compensated value hiding VM-exit overhead.
    // TSC_OFFSET is never modified — zero drift, zero monotonicity issues.
    //
    UINT64  tsc_cpuid_entry;        // TSC recorded at start of CPUID VM-exit handler
    BOOLEAN tsc_rdtsc_armed;        // TRUE = next RDTSC/RDTSCP should be compensated

    //
    // pending external interrupt for deferred re-injection
    // used when external-interrupt exiting is active but the guest
    // can't accept an interrupt right now (IF=0 or STI/MOV-SS blocking)
    //
    UINT8   pending_ext_vector;
    BOOLEAN has_pending_ext_interrupt;

    //
    // pending NMI for deferred delivery via NMI-window exiting
    // set when an NMI VM-exit interrupts IDT delivery of another event
    //
    BOOLEAN has_pending_nmi;

    // EPT Hook MTF tracking
    PEPT_HOOK_STATE mtf_hook_state;
    BOOLEAN         mtf_write_occurred;

    // guest DR0-DR3/DR6 saved on vm-exit, restored before vmresume
    UINT64  guest_dr0;
    UINT64  guest_dr1;
    UINT64  guest_dr2;
    UINT64  guest_dr3;
    UINT64  guest_dr6;
    BOOLEAN mov_dr_exiting;

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

#define VMCALL_TEST             0x00000001
#define VMCALL_VMXOFF           0x00000002

extern VIRTUAL_MACHINE_STATE * g_vcpu;
extern EPT_STATE *             g_ept;
extern UINT32                  g_cpu_count;
extern UINT64                  g_system_cr3;
extern UINT64 *                g_msr_bitmap_invalid;
