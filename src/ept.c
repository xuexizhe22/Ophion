/*
*   ept.c - extended page table (ept) initialization and management
*   identity-mapped ept with 2mb large pages, mtrr-aware memory typing
*   based on the stealthhv ept architecture: pml4 -> pml3 -> pml2 (2mb large pages)
*/
#include "hv.h"

static PEPT_HOOK_STATE
ept_find_hook_by_original_pfn(SIZE_T original_pfn)
{
    if (!g_ept)
        return NULL;

    for (PLIST_ENTRY entry = g_ept->hooked_pages.Flink;
         entry != &g_ept->hooked_pages;
         entry = entry->Flink)
    {
        PEPT_HOOK_STATE hook = CONTAINING_RECORD(entry, EPT_HOOK_STATE, ListEntry);
        if (hook->OriginalPfn == original_pfn)
        {
            return hook;
        }
    }

    return NULL;
}

static PVMM_EPT_DYNAMIC_SPLIT
ept_find_dynamic_split(_In_ PEPT_PML2_ENTRY target_entry)
{
    if (!g_ept || !target_entry)
        return NULL;

    for (PLIST_ENTRY entry = g_ept->dynamic_splits.Flink;
         entry != &g_ept->dynamic_splits;
         entry = entry->Flink)
    {
        PVMM_EPT_DYNAMIC_SPLIT split = CONTAINING_RECORD(entry, VMM_EPT_DYNAMIC_SPLIT, SplitList);
        if (split->u.Entry == target_entry)
        {
            return split;
        }
    }

    return NULL;
}

static VOID
ept_release_hook(_In_ PEPT_HOOK_STATE hook)
{
    if (!hook)
        return;

    if (hook->LockedMdl)
    {
        MmUnlockPages(hook->LockedMdl);
        IoFreeMdl(hook->LockedMdl);
    }

    if (hook->ProcessObject)
    {
        ObDereferenceObject(hook->ProcessObject);
    }

    if (hook->FakeVa)
    {
        MmFreeContiguousMemory(hook->FakeVa);
    }

    ExFreePoolWithTag(hook, HV_POOL_TAG);
}

VOID
ept_disable_hook(_In_ PEPT_HOOK_STATE hook)
{
    if (!hook || !hook->Enabled)
        return;

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        PVMM_EPT_PAGE_TABLE page_table = g_vcpu[i].ept_page_table;
        PEPT_PML1_ENTRY pml1 = ept_get_pml1(page_table, hook->OriginalPfn * PAGE_SIZE);

        if (pml1)
        {
            EPT_PML1_ENTRY new_entry;
            new_entry.AsUInt = pml1->AsUInt;
            new_entry.ReadAccess      = 1;
            new_entry.WriteAccess     = 1;
            new_entry.ExecuteAccess   = 1;
            new_entry.PageFrameNumber = hook->OriginalPfn;

            InterlockedExchange64((volatile LONG64 *)&pml1->AsUInt, new_entry.AsUInt);
        }

        if (g_vcpu[i].mtf_hook_state == hook)
        {
            g_vcpu[i].mtf_hook_state = NULL;
        }
    }

    hook->Enabled        = FALSE;
    hook->TargetCr3      = 0;
    hook->TargetPageBase = NULL;
}

BOOLEAN
ept_check_features(VOID)
{
    IA32_VMX_EPT_VPID_CAP_REGISTER vpid_reg;
    IA32_MTRR_DEF_TYPE_REGISTER    mtrr_def;

    vpid_reg.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);
    mtrr_def.AsUInt  = __readmsr(IA32_MTRR_DEF_TYPE);

    if (!vpid_reg.PageWalkLength4 || !vpid_reg.MemoryTypeWriteBack || !vpid_reg.Pde2MbPages)
    {
        DbgPrintEx(0, 0, "[hv] EPT: Missing required features (PW4=%d WB=%d 2MB=%d)\n",
                 vpid_reg.PageWalkLength4, vpid_reg.MemoryTypeWriteBack, vpid_reg.Pde2MbPages);
        return FALSE;
    }

    g_ept->ad_supported = vpid_reg.EptAccessedAndDirtyFlags ? TRUE : FALSE;

    g_ept->invvpid_supported              = vpid_reg.Invvpid ? TRUE : FALSE;
    g_ept->invvpid_individual_addr        = vpid_reg.InvvpidIndividualAddress ? TRUE : FALSE;
    g_ept->invvpid_single_context         = vpid_reg.InvvpidSingleContext ? TRUE : FALSE;
    g_ept->invvpid_all_contexts           = vpid_reg.InvvpidAllContexts ? TRUE : FALSE;
    g_ept->invvpid_single_retaining_globals = vpid_reg.InvvpidSingleContextRetainingGlobals ? TRUE : FALSE;

    DbgPrintEx(0, 0, "[hv] INVVPID caps: supported=%d individual=%d single=%d all=%d retaining_globals=%d\n",
             g_ept->invvpid_supported,
             g_ept->invvpid_individual_addr,
             g_ept->invvpid_single_context,
             g_ept->invvpid_all_contexts,
             g_ept->invvpid_single_retaining_globals);

    if (!mtrr_def.MtrrEnable)
    {
        DbgPrintEx(0, 0, "[hv] EPT: MTRR not enabled\n");
        return FALSE;
    }

    return TRUE;
}

UINT8
ept_get_memory_type(SIZE_T pfn, BOOLEAN is_large_page)
{
    SIZE_T page_addr = is_large_page ? pfn * SIZE_2_MB : pfn * PAGE_SIZE;
    UINT8  target_type    = (UINT8)-1;

    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];

        if (page_addr >= range->phys_base &&
            page_addr < range->phys_end)
        {
            if (range->fixed)
            {
                target_type = range->mem_type;
                break;
            }

            if (target_type == MEMORY_TYPE_UNCACHEABLE)
            {
                target_type = range->mem_type;
                break;
            }

            if (target_type == MEMORY_TYPE_WRITE_THROUGH ||
                range->mem_type == MEMORY_TYPE_WRITE_THROUGH)
            {
                if (target_type == MEMORY_TYPE_WRITE_BACK)
                {
                    target_type = MEMORY_TYPE_WRITE_THROUGH;
                    continue;
                }
            }

            target_type = range->mem_type;
        }
    }

    if (target_type == (UINT8)-1)
        target_type = g_ept->default_type;

    return target_type;
}

BOOLEAN
ept_build_mtrr_map(VOID)
{
    IA32_MTRR_CAPABILITIES_REGISTER mtrr_cap;
    IA32_MTRR_DEF_TYPE_REGISTER     mtrr_def;
    IA32_MTRR_PHYSBASE_REGISTER     cur_base;
    IA32_MTRR_PHYSMASK_REGISTER     cur_mask;
    MTRR_RANGE_DESCRIPTOR *         desc;

    mtrr_cap.AsUInt     = __readmsr(IA32_MTRR_CAPABILITIES);
    mtrr_def.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

    if (!mtrr_def.MtrrEnable)
    {
        g_ept->default_type = MEMORY_TYPE_UNCACHEABLE;
        return TRUE;
    }

    g_ept->default_type = (UINT8)mtrr_def.DefaultMemoryType;

    //
    // fixed-range mtrrs (64K, 16K, 4K regions)
    //
    if (mtrr_cap.FixedRangeSupported && mtrr_def.FixedRangeMtrrEnable)
    {
        //
        // IA32_MTRR_FIX64K_00000: 8 x 64KB regions from 0x00000 to 0x7FFFF
        //
        IA32_MTRR_FIXED_RANGE_TYPE k64_types = { __readmsr(IA32_MTRR_FIX64K_00000) };
        for (UINT32 i = 0; i < 8; i++)
        {
            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->mem_type          = k64_types.s.Types[i];
            desc->phys_base = 0x10000 * i;
            desc->phys_end  = 0x10000 * i + 0x10000 - 1;
            desc->fixed          = TRUE;
        }

        //
        // IA32_MTRR_FIX16K_80000/A0000: 16 x 16KB regions
        //
        for (UINT32 i = 0; i < 2; i++)
        {
            IA32_MTRR_FIXED_RANGE_TYPE k16_types = { __readmsr(IA32_MTRR_FIX16K_80000 + i) };
            for (UINT32 j = 0; j < 8; j++)
            {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type          = k16_types.s.Types[j];
                desc->phys_base = 0x80000 + (i * 0x20000) + (j * 0x4000);
                desc->phys_end  = desc->phys_base + 0x4000 - 1;
                desc->fixed          = TRUE;
            }
        }

        //
        // IA32_MTRR_FIX4K_C0000 through FIX4K_F8000: 64 x 4KB regions
        //
        for (UINT32 i = 0; i < 8; i++)
        {
            IA32_MTRR_FIXED_RANGE_TYPE k4_types = { __readmsr(IA32_MTRR_FIX4K_C0000 + i) };
            for (UINT32 j = 0; j < 8; j++)
            {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type          = k4_types.s.Types[j];
                desc->phys_base = 0xC0000 + (i * 0x8000) + (j * 0x1000);
                desc->phys_end  = desc->phys_base + 0x1000 - 1;
                desc->fixed          = TRUE;
            }
        }
    }

    //
    // variable-range mtrrs
    //
    for (UINT32 i = 0; i < mtrr_cap.VariableRangeCount; i++)
    {
        cur_base.AsUInt = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
        cur_mask.AsUInt = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

        if (cur_mask.Valid)
        {
            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->phys_base = cur_base.PageFrameNumber * PAGE_SIZE;

            ULONG mask_bits;
            _BitScanForward64(&mask_bits, cur_mask.PageFrameNumber * PAGE_SIZE);

            desc->phys_end = desc->phys_base + ((1ULL << mask_bits) - 1ULL);
            desc->mem_type         = (UINT8)cur_base.Type;
            desc->fixed         = FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
ept_valid_for_large_page(SIZE_T pfn)
{
    SIZE_T start_addr = pfn * SIZE_2_MB;
    SIZE_T end_addr   = start_addr + SIZE_2_MB - 1;

    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];

        if ((start_addr <= range->phys_end && end_addr > range->phys_end) ||
            (start_addr < range->phys_base && end_addr >= range->phys_base))
        {
            return FALSE;  // crosses MTRR boundary — must split to 4KB
        }
    }

    return TRUE;
}

BOOLEAN
ept_setup_pml2(PVMM_EPT_PAGE_TABLE page_table, PEPT_PML2_ENTRY new_entry, SIZE_T pfn)
{
    UNREFERENCED_PARAMETER(page_table);
    new_entry->PageFrameNumber = pfn;

    if (ept_valid_for_large_page(pfn))
    {
        new_entry->MemoryType = ept_get_memory_type(pfn, TRUE);
        return TRUE;
    }
    else
    {
        //
        // the 2MB range crosses MTRR boundaries — needs to be split to 4KB
        // for the skeleton, we just log a warning. you'll implement
        // ept_split_large_page as needed for EPT hooks.
        //
        new_entry->MemoryType = ept_get_memory_type(pfn, TRUE);
        DbgPrintEx(0, 0, "[hv] EPT: Page at PFN 0x%llx crosses MTRR boundary (split recommended)\n",
                 pfn);
        return TRUE;
    }
}

/*
*   allocate and create identity-mapped ept page table
*   maps all physical memory 1:1 (guest physical = host physical)
*   pml4 (512 entries) -> pml3 (512 entries) -> pml2 (512 x 512 = 262144 entries)
*/
PVMM_EPT_PAGE_TABLE
ept_alloc_identity_map(VOID)
{
    PHYSICAL_ADDRESS    max_phys;
    PVMM_EPT_PAGE_TABLE page_table;
    EPT_PML2_ENTRY      pml2_tmpl;

    max_phys.QuadPart = MAXULONG64;

    page_table = (PVMM_EPT_PAGE_TABLE)MmAllocateContiguousMemory(
        sizeof(VMM_EPT_PAGE_TABLE), max_phys);
    if (!page_table)
        return NULL;

    RtlZeroMemory(page_table, sizeof(VMM_EPT_PAGE_TABLE));

    page_table->PML4[0].ReadAccess    = 1;
    page_table->PML4[0].WriteAccess   = 1;
    page_table->PML4[0].ExecuteAccess = 1;
    page_table->PML4[0].PageFrameNumber = va_to_pa(&page_table->PML3[0]) / PAGE_SIZE;

    for (SIZE_T i = 0; i < VMM_EPT_PML3E_COUNT; i++)
    {
        page_table->PML3[i].ReadAccess    = 1;
        page_table->PML3[i].WriteAccess   = 1;
        page_table->PML3[i].ExecuteAccess = 1;
        page_table->PML3[i].PageFrameNumber = va_to_pa(&page_table->PML2[i][0]) / PAGE_SIZE;
    }

    pml2_tmpl.AsUInt        = 0;
    pml2_tmpl.ReadAccess    = 1;
    pml2_tmpl.WriteAccess   = 1;
    pml2_tmpl.ExecuteAccess = 1;
    pml2_tmpl.LargePage     = 1;

    __stosq((SIZE_T *)&page_table->PML2[0], pml2_tmpl.AsUInt,
            VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

    for (SIZE_T group = 0; group < VMM_EPT_PML3E_COUNT; group++)
    {
        for (SIZE_T entry_idx = 0; entry_idx < VMM_EPT_PML2E_COUNT; entry_idx++)
        {
            ept_setup_pml2(page_table,
                              &page_table->PML2[group][entry_idx],
                              (group * VMM_EPT_PML2E_COUNT) + entry_idx);
        }
    }

    return page_table;
}

BOOLEAN
ept_init(VOID)
{
    EPT_POINTER eptp = {0};

    g_ept = (EPT_STATE *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(EPT_STATE), HV_POOL_TAG);
    if (!g_ept)
        return FALSE;

    RtlZeroMemory(g_ept, sizeof(EPT_STATE));

    InitializeListHead(&g_ept->hooked_pages);
    InitializeListHead(&g_ept->dynamic_splits);

    if (!ept_check_features())
        return FALSE;

    if (!ept_build_mtrr_map())
        return FALSE;

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        PVMM_EPT_PAGE_TABLE page_table = ept_alloc_identity_map();
        if (!page_table)
        {
            DbgPrintEx(0, 0, "[hv] EPT: Failed to allocate page table for core %u\n", i);
            return FALSE;
        }

        g_vcpu[i].ept_page_table = page_table;

        //
        // build EPT pointer
        // memory type for EPT paging structures = WB (most efficient, validated
        // by ept_check_features checking memoryTypeWriteBack capability).
        //
        eptp.MemoryType               = MEMORY_TYPE_WRITE_BACK;
        eptp.EnableAccessAndDirtyFlags = g_ept->ad_supported;
        eptp.PageWalkLength           = 3;  // 4-level walk (value = levels - 1)
        eptp.PageFrameNumber          = va_to_pa(&page_table->PML4) / PAGE_SIZE;

        g_vcpu[i].ept_pointer = eptp;
    }

    DbgPrintEx(0, 0, "[hv] EPT initialized for %u processors\n", g_cpu_count);
    return TRUE;
}

/*
*   split a 2mb page into 512 4kb pages (for ept hooks)
*   placeholder — implement when you need fine-grained memory control
*/
BOOLEAN
ept_split_large_page(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    PEPT_PML2_ENTRY target;
    PVMM_EPT_DYNAMIC_SPLIT new_split;
    EPT_PML1_ENTRY entry_tmpl;
    EPT_PML2_POINTER new_ptr;

    target = ept_get_pml2(page_table, phys_addr);
    if (!target || !target->LargePage)
        return FALSE;

    new_split = (PVMM_EPT_DYNAMIC_SPLIT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(VMM_EPT_DYNAMIC_SPLIT), HV_POOL_TAG);
    if (!new_split)
        return FALSE;

    RtlZeroMemory(new_split, sizeof(VMM_EPT_DYNAMIC_SPLIT));
    new_split->u.Entry = target;

    entry_tmpl.AsUInt        = 0;
    entry_tmpl.ReadAccess    = 1;
    entry_tmpl.WriteAccess   = 1;
    entry_tmpl.ExecuteAccess = 1;

    __stosq((SIZE_T *)&new_split->PML1[0], entry_tmpl.AsUInt, VMM_EPT_PML1E_COUNT);

    for (SIZE_T i = 0; i < VMM_EPT_PML1E_COUNT; i++)
    {
        new_split->PML1[i].PageFrameNumber = ((target->PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + i;
        new_split->PML1[i].MemoryType      = ept_get_memory_type(new_split->PML1[i].PageFrameNumber, FALSE);
    }

    new_ptr.AsUInt            = 0;
    new_ptr.ReadAccess        = 1;
    new_ptr.WriteAccess       = 1;
    new_ptr.ExecuteAccess     = 1;
    new_ptr.PageFrameNumber   = va_to_pa(&new_split->PML1[0]) / PAGE_SIZE;

    RtlCopyMemory(target, &new_ptr, sizeof(new_ptr));
    InsertTailList(&g_ept->dynamic_splits, &new_split->SplitList);

    return TRUE;
}

PEPT_PML2_ENTRY
ept_get_pml2(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    SIZE_T dir  = ADDRMASK_EPT_PML2_INDEX(phys_addr);
    SIZE_T dir_p = ADDRMASK_EPT_PML3_INDEX(phys_addr);
    SIZE_T pml4 = ADDRMASK_EPT_PML4_INDEX(phys_addr);

    if (pml4 > 0)
        return NULL;

    return &page_table->PML2[dir_p][dir];
}

/*
*   get pml1 entry for a physical address (only if page is split)
*/
PEPT_PML1_ENTRY
ept_get_pml1(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    SIZE_T dir  = ADDRMASK_EPT_PML2_INDEX(phys_addr);
    SIZE_T dir_p = ADDRMASK_EPT_PML3_INDEX(phys_addr);
    SIZE_T pml4 = ADDRMASK_EPT_PML4_INDEX(phys_addr);

    if (pml4 > 0)
        return NULL;

    PEPT_PML2_ENTRY pml2 = &page_table->PML2[dir_p][dir];
    if (pml2->LargePage)
        return NULL;  // not split

    PVMM_EPT_DYNAMIC_SPLIT split = ept_find_dynamic_split(pml2);
    if (!split)
        return NULL;

    return &split->PML1[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
}

BOOLEAN
ept_hook_page(
    SIZE_T phys_addr,
    PVOID source_page_va,
    PVOID target_page_base,
    UINT64 target_cr3,
    SIZE_T patch_offset,
    PVOID patch_bytes,
    SIZE_T patch_size,
    PMDL locked_mdl,
    HANDLE process_id,
    PEPROCESS target_process)
{
    SIZE_T target_pfn = phys_addr / PAGE_SIZE;

    if (!target_pfn || !source_page_va || !patch_bytes || !locked_mdl)
        return FALSE;

    if (patch_size == 0 || patch_offset >= PAGE_SIZE || (patch_offset + patch_size) > PAGE_SIZE)
        return FALSE;

    PEPT_HOOK_STATE existing_hook = ept_find_hook_by_original_pfn(target_pfn);
    if (existing_hook)
    {
        RtlCopyMemory(existing_hook->FakeVa, source_page_va, PAGE_SIZE);
        RtlCopyMemory((PUCHAR)existing_hook->FakeVa + patch_offset, patch_bytes, patch_size);

        if (existing_hook->LockedMdl)
        {
            MmUnlockPages(existing_hook->LockedMdl);
            IoFreeMdl(existing_hook->LockedMdl);
        }

        existing_hook->OriginalPageVa = source_page_va;
        existing_hook->TargetPageBase = target_page_base;
        existing_hook->TargetCr3      = target_cr3 & ~0xFFFULL;
        existing_hook->LockedMdl      = locked_mdl;
        existing_hook->ProcessId      = process_id;
        existing_hook->PatchOffset    = patch_offset;
        existing_hook->PatchSize      = patch_size;
        existing_hook->Enabled        = TRUE;

        if (existing_hook->ProcessObject != target_process)
        {
            if (target_process)
                ObReferenceObject(target_process);

            if (existing_hook->ProcessObject)
                ObDereferenceObject(existing_hook->ProcessObject);

            existing_hook->ProcessObject = target_process;
        }

        for (UINT32 i = 0; i < g_cpu_count; i++)
        {
            PVMM_EPT_PAGE_TABLE page_table = g_vcpu[i].ept_page_table;
            PEPT_PML1_ENTRY pml1 = ept_get_pml1(page_table, target_pfn * PAGE_SIZE);

            if (!pml1)
            {
                DbgPrintEx(0, 0, "[hv] EPT Hook refresh failed: PML1 lookup failed on CPU %u for PFN 0x%llx\n",
                         i, target_pfn);
                existing_hook->Enabled = FALSE;
                return FALSE;
            }

            pml1->ReadAccess      = 0;
            pml1->WriteAccess     = 0;
            pml1->ExecuteAccess   = 1;
            pml1->PageFrameNumber = existing_hook->FakePfn;
        }

        // Make sure every CPU sees the refreshed fake page contents.
        asm_vmx_vmcall(VMCALL_TEST, 0, 0, 0);

        DbgPrintEx(0, 0, "[hv] EPT Hook refreshed for PFN 0x%llx (PID=%p, offset=0x%Ix, size=0x%Ix)\n",
                   existing_hook->OriginalPfn, existing_hook->ProcessId, existing_hook->PatchOffset, existing_hook->PatchSize);
        return TRUE;
    }

    PEPT_HOOK_STATE hook = (PEPT_HOOK_STATE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(EPT_HOOK_STATE), HV_POOL_TAG);

    if (!hook)
        return FALSE;

    PHYSICAL_ADDRESS high_addr = { 0 };
    high_addr.QuadPart = MAXULONG64;
    PVOID fake_page = MmAllocateContiguousMemory(PAGE_SIZE, high_addr);

    if (!fake_page)
    {
        ExFreePoolWithTag(hook, HV_POOL_TAG);
        return FALSE;
    }

    RtlZeroMemory(hook, sizeof(EPT_HOOK_STATE));
    RtlCopyMemory(fake_page, source_page_va, PAGE_SIZE);
    RtlCopyMemory((PUCHAR)fake_page + patch_offset, patch_bytes, patch_size);

    hook->OriginalPfn = target_pfn;
    hook->FakePfn     = va_to_pa(fake_page) / PAGE_SIZE;
    hook->TargetCr3   = target_cr3 & ~0xFFFULL;
    hook->TargetPageBase = target_page_base;
    hook->OriginalPageVa = source_page_va;
    hook->FakeVa      = fake_page;
    hook->ProcessObject = NULL;
    hook->ProcessId   = process_id;
    hook->PatchOffset = patch_offset;
    hook->PatchSize   = patch_size;
    hook->Enabled     = TRUE;

    if (target_process)
    {
        ObReferenceObject(target_process);
        hook->ProcessObject = target_process;
    }

    // Split large page and update PML1 across all cores
    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        PVMM_EPT_PAGE_TABLE page_table = g_vcpu[i].ept_page_table;

        PEPT_PML2_ENTRY pml2 = ept_get_pml2(page_table, phys_addr);
        if (pml2 && pml2->LargePage)
        {
            if (!ept_split_large_page(page_table, phys_addr))
            {
                DbgPrintEx(0, 0, "[hv] EPT Hook failed: split_large_page failed on CPU %u for PA 0x%llx\n",
                         i, phys_addr);
                ept_release_hook(hook);
                return FALSE;
            }
        }

        PEPT_PML1_ENTRY pml1 = ept_get_pml1(page_table, phys_addr);
        if (pml1)
        {
            // Set up EPT entry to redirect execution to the fake page
            pml1->ReadAccess      = 0;
            pml1->WriteAccess     = 0;
            pml1->ExecuteAccess   = 1;
            pml1->PageFrameNumber = hook->FakePfn;
        }
        else
        {
            DbgPrintEx(0, 0, "[hv] EPT Hook failed: PML1 lookup failed on CPU %u for PA 0x%llx\n",
                     i, phys_addr);
            ept_release_hook(hook);
            return FALSE;
        }
    }



    hook->LockedMdl = locked_mdl;
    InsertTailList(&g_ept->hooked_pages, &hook->ListEntry);

    // Trigger a VM-exit on the current CPU so INVEPT can make the new mapping visible.
    asm_vmx_vmcall(VMCALL_TEST, 0, 0, 0);

    // 触发当前核心的 VM-Exit，在 VMCALL_TEST 处理器中调用 ept_invept_all()
    // Intel SDM 保证基于同一个 EPT Pointer 的 INVEPT 可以全局生效，不需要用 DPC 广播死锁所有核心
    asm_vmx_vmcall(VMCALL_TEST, 0, 0, 0);

    DbgPrintEx(0, 0, "[hv] EPT Hook installed at PFN 0x%llx (Fake: 0x%llx, PID=%p, CR3=0x%llx, page=%p, offset=0x%Ix, size=0x%Ix)\n",
               hook->OriginalPfn, hook->FakePfn, hook->ProcessId, hook->TargetCr3, hook->TargetPageBase, hook->PatchOffset, hook->PatchSize);

    return TRUE;
}

VOID
ept_cleanup_state(VOID)
{
    if (!g_ept)
        return;

    while (!IsListEmpty(&g_ept->hooked_pages))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_ept->hooked_pages);
        PEPT_HOOK_STATE hook = CONTAINING_RECORD(entry, EPT_HOOK_STATE, ListEntry);
        ept_release_hook(hook);
    }

    while (!IsListEmpty(&g_ept->dynamic_splits))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_ept->dynamic_splits);
        PVMM_EPT_DYNAMIC_SPLIT split = CONTAINING_RECORD(entry, VMM_EPT_DYNAMIC_SPLIT, SplitList);
        ExFreePoolWithTag(split, HV_POOL_TAG);
    }
}

VOID
ept_invept_single(EPT_POINTER ept_ptr)
{
    INVEPT_DESCRIPTOR desc = {0};
    desc.EptPointer = ept_ptr;
    asm_invept(InveptSingleContext, &desc);
}

VOID
ept_invept_all(VOID)
{
    INVEPT_DESCRIPTOR desc = {0};
    asm_invept(InveptAllContexts, &desc);
}

VOID
vpid_invvpid_single(UINT16 vpid)
{
    INVVPID_DESCRIPTOR desc = {0};
    desc.Vpid = vpid;
    asm_invvpid(InvvpidSingleContext, &desc);
}
