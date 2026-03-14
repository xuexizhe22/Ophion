/*
*   ept.c - extended page table (ept) initialization and management
*   identity-mapped ept with 2mb large pages, mtrr-aware memory typing
*   based on the stealthhv ept architecture: pml4 -> pml3 -> pml2 (2mb large pages)
*/
#include "hv.h"

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

    PEPT_PML2_POINTER ptr = (PEPT_PML2_POINTER)pml2;
    PEPT_PML1_ENTRY pml1 = (PEPT_PML1_ENTRY)pa_to_va(
        ptr->PageFrameNumber * PAGE_SIZE);

    if (!pml1)
        return NULL;

    return &pml1[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
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
