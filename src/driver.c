/*
*   driver.c - windows kernel driver entry point for the hypervisor
*   creates a device object, symbolic link, and initializes vmx
*   provides ioctl interface for usermode loader communication
*/
#include <ntifs.h>
#include "hv.h"

#define DEVICE_NAME     L"\\Device\\Ophion"
#define SYMLINK_NAME    L"\\DosDevices\\Ophion"

#define IOCTL_BASE      0x800
#define IOCTL_HV_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_QUERY_HOOK_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_BATCH_BEGIN CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_BATCH_END CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_UNHOOK CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_UNHOOK_ALL CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_UNHOOK_PAGE CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_SET_FAST_RULES CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EPT_HOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
    UCHAR  PatchBytes[16];
    UINT32 PatchSize;
} EPT_HOOK_REQUEST, *PEPT_HOOK_REQUEST;

typedef struct _EPT_HOOK_REQUEST32 {
    UINT32 ProcessId;
    UINT32 VirtualAddress;
    UCHAR  PatchBytes[16];
    UINT32 PatchSize;
} EPT_HOOK_REQUEST32, *PEPT_HOOK_REQUEST32;

typedef struct _EPT_HOOK_STATS_QUERY {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
} EPT_HOOK_STATS_QUERY, *PEPT_HOOK_STATS_QUERY;

typedef struct _EPT_HOOK_STATS_QUERY32 {
    UINT32 ProcessId;
    UINT32 VirtualAddress;
} EPT_HOOK_STATS_QUERY32, *PEPT_HOOK_STATS_QUERY32;

typedef struct _EPT_HOOK_UNHOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
} EPT_HOOK_UNHOOK_REQUEST, *PEPT_HOOK_UNHOOK_REQUEST;

typedef struct _EPT_HOOK_UNHOOK_REQUEST32 {
    UINT32 ProcessId;
    UINT32 VirtualAddress;
} EPT_HOOK_UNHOOK_REQUEST32, *PEPT_HOOK_UNHOOK_REQUEST32;

typedef struct _EPT_HOOK_FAST_RULES_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
    UINT32 RuleCount;
    UINT32 Reserved;
    EPT_HOOK_FAST_RULE Rules[EPT_HOOK_MAX_FAST_RULES];
} EPT_HOOK_FAST_RULES_REQUEST, *PEPT_HOOK_FAST_RULES_REQUEST;

typedef struct _EPT_HOOK_FAST_RULES_REQUEST32 {
    UINT32 ProcessId;
    UINT32 VirtualAddress;
    UINT32 RuleCount;
    UINT32 Reserved;
    EPT_HOOK_FAST_RULE Rules[EPT_HOOK_MAX_FAST_RULES];
} EPT_HOOK_FAST_RULES_REQUEST32, *PEPT_HOOK_FAST_RULES_REQUEST32;

typedef struct _EPT_HOOK_HOTSPOT_RESULT {
    UINT64 Rip;
    UINT64 GuestPhysical;
    UINT64 GuestLinear;
    UINT64 HitCount;
    UINT32 Flags;
    UINT32 Reserved;
} EPT_HOOK_HOTSPOT_RESULT, *PEPT_HOOK_HOTSPOT_RESULT;

typedef struct _EPT_HOOK_STATS_RESULT {
    UINT32 Size;
    UINT32 ProcessId;
    UINT64 RequestedAddress;
    UINT64 TargetPageBase;
    UINT64 TargetCr3;
    UINT64 OriginalPfn;
    UINT64 FakePfn;
    UINT64 PatchOffset;
    UINT64 PatchSize;
    UINT64 ExecuteViolations;
    UINT64 ReadViolations;
    UINT64 WriteViolations;
    UINT64 ContextMismatchViolations;
    UINT64 MtfCount;
    UINT64 EmulationSuccesses;
    UINT64 EmulationFailures;
    UINT64 LastViolationRip;
    UINT64 LastGuestPhysical;
    UINT64 LastGuestLinear;
    UINT32 LastViolationFlags;
    UINT32 Enabled;
    UINT32 HotspotCount;
    UINT32 HotspotSampleEvery;
    EPT_HOOK_HOTSPOT_RESULT Hotspots[EPT_HOOK_HOTSPOT_COUNT];
    // FF-raw emulation diagnostics
    UINT64 FfRawFailMode;
    UINT64 FfRawFailInsnRead;
    UINT64 FfRawFailOpcode;
    UINT64 FfRawFailAddrCalc;
    UINT64 FfRawFailTargetRead;
    UINT64 FfRawFailStack;
    UINT64 FfRawSuccess;
    UINT64 FfShortcutSuccess;
    UINT64 FfShortcutFail;
} EPT_HOOK_STATS_RESULT, *PEPT_HOOK_STATS_RESULT;

static HANDLE g_hook_guard_thread = NULL;
static KEVENT g_hook_guard_stop_event;

static NTSTATUS DriverCreateClose(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverIoControl(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverHandleEptHook(_In_ PEPT_HOOK_REQUEST req);
static NTSTATUS DriverHandleEptUnhook(_In_ PEPT_HOOK_UNHOOK_REQUEST req);
static NTSTATUS DriverHandleEptUnhookAll(VOID);
static NTSTATUS DriverHandleEptUnhookPage(_In_ PEPT_HOOK_UNHOOK_REQUEST req);
static NTSTATUS DriverHandleEptSetFastRules(_In_ PEPT_HOOK_FAST_RULES_REQUEST req);
static NTSTATUS DriverQueryHookStats(_In_ PEPT_HOOK_STATS_QUERY query, _Out_ PEPT_HOOK_STATS_RESULT result);
static NTSTATUS DriverPreflightCheck(VOID);
static VOID DriverScanExitedHooks(VOID);
static VOID DriverHookGuardThread(_In_ PVOID start_context);

static VOID
DriverAcquireHotspotLock(_Inout_ PEPT_HOOK_STATE hook)
{
    while (InterlockedCompareExchange(&hook->HotspotLock, 1, 0) != 0)
    {
        YieldProcessor();
    }
}

static VOID
DriverReleaseHotspotLock(_Inout_ PEPT_HOOK_STATE hook)
{
    InterlockedExchange(&hook->HotspotLock, 0);
}

static VOID
DriverSortHotspotsDescending(_Inout_updates_(EPT_HOOK_HOTSPOT_COUNT) PEPT_HOOK_HOTSPOT_RESULT hotspots)
{
    for (UINT32 i = 0; i < EPT_HOOK_HOTSPOT_COUNT; i++)
    {
        UINT32 best = i;

        for (UINT32 j = i + 1; j < EPT_HOOK_HOTSPOT_COUNT; j++)
        {
            if (hotspots[j].HitCount > hotspots[best].HitCount)
                best = j;
        }

        if (best != i)
        {
            EPT_HOOK_HOTSPOT_RESULT temp = hotspots[i];
            hotspots[i] = hotspots[best];
            hotspots[best] = temp;
        }
    }
}

static VOID
DriverCopyHookHotspots(_In_ PEPT_HOOK_STATE hook, _Out_ PEPT_HOOK_STATS_RESULT result)
{
    EPT_HOOK_HOTSPOT_RESULT snapshot[EPT_HOOK_HOTSPOT_COUNT];

    if (!hook || !result)
        return;

    RtlZeroMemory(snapshot, sizeof(snapshot));
    result->HotspotSampleEvery = EPT_HOOK_HOTSPOT_SAMPLE_EVERY;

    DriverAcquireHotspotLock(hook);
    for (UINT32 i = 0; i < EPT_HOOK_HOTSPOT_COUNT; i++)
    {
        snapshot[i].Rip           = hook->Hotspots[i].Rip;
        snapshot[i].GuestPhysical = hook->Hotspots[i].GuestPhysical;
        snapshot[i].GuestLinear   = hook->Hotspots[i].GuestLinear;
        snapshot[i].HitCount      = hook->Hotspots[i].HitCount;
        snapshot[i].Flags         = hook->Hotspots[i].Flags;
        snapshot[i].Reserved      = hook->Hotspots[i].Reserved;
    }
    DriverReleaseHotspotLock(hook);

    DriverSortHotspotsDescending(snapshot);
    for (UINT32 i = 0; i < EPT_HOOK_HOTSPOT_COUNT; i++)
    {
        result->Hotspots[i] = snapshot[i];
        if (snapshot[i].HitCount != 0)
            result->HotspotCount += 1;
    }
}

static PEPT_HOOK_STATE
DriverFindHookByProcessPage(_In_ UINT32 process_id, _In_ PVOID page_base)
{
    if (!g_ept)
        return NULL;

    for (PLIST_ENTRY entry = g_ept->hooked_pages.Flink;
         entry != &g_ept->hooked_pages;
         entry = entry->Flink)
    {
        PEPT_HOOK_STATE hook = CONTAINING_RECORD(entry, EPT_HOOK_STATE, ListEntry);
        if (!hook->Enabled)
            continue;

        if ((UINT32)(ULONG_PTR)hook->ProcessId != process_id)
            continue;

        if (hook->TargetPageBase == page_base)
            return hook;
    }

    return NULL;
}

static PEPT_HOOK_STATE
DriverFindHookByProcessPfn(_In_ UINT32 process_id, _In_ SIZE_T page_pfn)
{
    if (!g_ept)
        return NULL;

    for (PLIST_ENTRY entry = g_ept->hooked_pages.Flink;
         entry != &g_ept->hooked_pages;
         entry = entry->Flink)
    {
        PEPT_HOOK_STATE hook = CONTAINING_RECORD(entry, EPT_HOOK_STATE, ListEntry);
        if (!hook->Enabled)
            continue;

        if ((UINT32)(ULONG_PTR)hook->ProcessId != process_id)
            continue;

        if (hook->OriginalPfn == page_pfn)
            return hook;
    }

    return NULL;
}

static NTSTATUS
DriverResolveProcessPagePfn(
    _In_ UINT32 process_id,
    _In_ PVOID virtual_address,
    _Out_ SIZE_T *page_pfn)
{
    NTSTATUS status;
    PEPROCESS target_process = NULL;
    KAPC_STATE apc_state;
    PMDL mdl = NULL;
    BOOLEAN pages_locked = FALSE;
    PPFN_NUMBER pfns = NULL;
    PVOID page_base;

    if (!virtual_address || !page_pfn)
        return STATUS_INVALID_PARAMETER;

    *page_pfn = 0;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)process_id, &target_process);
    if (!NT_SUCCESS(status))
        return status;

    page_base = PAGE_ALIGN(virtual_address);
    KeStackAttachProcess(target_process, &apc_state);

    mdl = IoAllocateMdl(page_base, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    __try
    {
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
        pages_locked = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        goto Exit;
    }

    pfns = MmGetMdlPfnArray(mdl);
    if (!pfns)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    *page_pfn = (SIZE_T)pfns[0];
    status = STATUS_SUCCESS;

Exit:
    if (pages_locked)
        MmUnlockPages(mdl);

    if (mdl)
        IoFreeMdl(mdl);

    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(target_process);
    return status;
}

static BOOLEAN
DriverHypervisorVendorEquals(_In_reads_(12) const CHAR * vendor)
{
    return RtlCompareMemory(
        &g_stealth_cpuid_cache.hypervisor_vendor[0],
        vendor,
        12) == 12;
}

static NTSTATUS
DriverPreflightCheck(VOID)
{
    if (!vmx_check_support())
    {
        DbgPrintEx(0, 0, "[hv] Preflight failed: VMX not supported or disabled by firmware\n");
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

#if STEALTH_CPUID_CACHING
    stealth_init_cpuid_cache();

    if (g_stealth_cpuid_cache.outer_hypervisor_present)
    {
        if (DriverHypervisorVendorEquals("VMwareVMware"))
        {
            DbgPrintEx(0, 0, "[hv] Preflight: VMware outer hypervisor detected, nested compatibility path allowed\n");
            return STATUS_SUCCESS;
        }

        DbgPrintEx(0, 0, "[hv] Preflight blocked: outer hypervisor %.4s%.4s%.4s is not in the allow-list\n",
                 (const CHAR *)&g_stealth_cpuid_cache.hypervisor_vendor[0],
                 (const CHAR *)&g_stealth_cpuid_cache.hypervisor_vendor[1],
                 (const CHAR *)&g_stealth_cpuid_cache.hypervisor_vendor[2]);
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }
#endif

    return STATUS_SUCCESS;
}

static VOID
DriverScanExitedHooks(VOID)
{
    BOOLEAN updated = FALSE;

    if (!g_ept)
        return;

    for (PLIST_ENTRY entry = g_ept->hooked_pages.Flink;
         entry != &g_ept->hooked_pages;
         entry = entry->Flink)
    {
        PEPT_HOOK_STATE hook = CONTAINING_RECORD(entry, EPT_HOOK_STATE, ListEntry);

        if (!hook->Enabled || !hook->ProcessObject)
            continue;

        if (PsGetProcessExitStatus(hook->ProcessObject) != STATUS_PENDING)
        {
            DbgPrintEx(0, 0, "[hv] Auto-disabling EPT hook for exited process PID=%p\n", hook->ProcessId);
            ept_disable_hook(hook);
            updated = TRUE;
        }
    }

    if (updated && g_vcpu)
    {
        broadcast_update_ept();
    }
}

static VOID
DriverHookGuardThread(_In_ PVOID start_context)
{
    LARGE_INTEGER interval;
    NTSTATUS wait_status;

    UNREFERENCED_PARAMETER(start_context);

    interval.QuadPart = -10 * 1000 * 1000;

    for (;;)
    {
        wait_status = KeWaitForSingleObject(
            &g_hook_guard_stop_event,
            Executive,
            KernelMode,
            FALSE,
            &interval);

        if (wait_status == STATUS_SUCCESS)
        {
            PsTerminateSystemThread(STATUS_SUCCESS);
        }

        DriverScanExitedHooks();
    }
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNICODE_STRING symlink;

    DbgPrintEx(0, 0, "[hv] Unloading hypervisor driver...\n");

    if (g_hook_guard_thread)
    {
        KeSetEvent(&g_hook_guard_stop_event, IO_NO_INCREMENT, FALSE);
        ZwWaitForSingleObject(g_hook_guard_thread, FALSE, NULL);
        ZwClose(g_hook_guard_thread);
        g_hook_guard_thread = NULL;
    }

    broadcast_terminate_all();
    vmx_terminate();

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (driver_obj->DeviceObject)
    {
        IoDeleteDevice(driver_obj->DeviceObject);
    }

    DbgPrintEx(0, 0, "[hv] Driver unloaded.\n");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    NTSTATUS       status;
    PDEVICE_OBJECT device_obj = NULL;
    UNICODE_STRING device_name;
    UNICODE_STRING symlink;

    UNREFERENCED_PARAMETER(registry_path);

    DbgPrintEx(0, 0, "[hv] DriverEntry - Hypervisor initializing...\n");

    status = DriverPreflightCheck();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[hv] Driver preflight failed: 0x%X\n", status);
        return status;
    }

    RtlInitUnicodeString(&device_name, DEVICE_NAME);
    status = IoCreateDevice(
        driver_obj,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device_obj);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[hv] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &device_name);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[hv] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(device_obj);
        return status;
    }

    driver_obj->DriverUnload                         = DriverUnload;
    driver_obj->MajorFunction[IRP_MJ_CREATE]         = DriverCreateClose;
    driver_obj->MajorFunction[IRP_MJ_CLOSE]          = DriverCreateClose;
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

    if (!vmx_init())
    {
        DbgPrintEx(0, 0, "[hv] VMX initialization FAILED!\n");
        broadcast_terminate_all();
        vmx_terminate();
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(device_obj);
        return STATUS_HV_OPERATION_FAILED;
    }

    KeInitializeEvent(&g_hook_guard_stop_event, NotificationEvent, FALSE);
    status = PsCreateSystemThread(
        &g_hook_guard_thread,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        DriverHookGuardThread,
        NULL);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "[hv] Failed to start hook guard thread: 0x%X\n", status);
        broadcast_terminate_all();
        vmx_terminate();
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(device_obj);
        return status;
    }

    DbgPrintEx(0, 0, "[hv] Hypervisor loaded and active on all cores!\n");
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverCreateClose(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverHandleEptHook(
    _In_ PEPT_HOOK_REQUEST req)
{
    NTSTATUS    status;
    PEPROCESS   target_process = NULL;
    KAPC_STATE  apc_state;
    PVOID       page_base;
    SIZE_T      page_offset;
    UINT64      target_cr3 = 0;
    PMDL        locked_mdl = NULL;
    BOOLEAN     pages_locked = FALSE;
    PVOID       source_page = NULL;
    PPFN_NUMBER pfns = NULL;
    SIZE_T      phys_addr = 0;

    if (!req->VirtualAddress)
    {
        return STATUS_INVALID_ADDRESS;
    }

    if (req->PatchSize == 0 || req->PatchSize > sizeof(req->PatchBytes))
    {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    page_offset = BYTE_OFFSET(req->VirtualAddress);
    if ((PAGE_SIZE - page_offset) < req->PatchSize)
    {
        DbgPrintEx(0, 0, "[hv] IOCTL_HV_EPT_HOOK rejected cross-page patch (offset=0x%Ix size=0x%X)\n",
                 page_offset, req->PatchSize);
        return STATUS_NOT_SUPPORTED;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &target_process);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    page_base = PAGE_ALIGN(req->VirtualAddress);

    KeStackAttachProcess(target_process, &apc_state);
    target_cr3 = __readcr3() & ~0xFFFULL;

    locked_mdl = IoAllocateMdl(page_base, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!locked_mdl)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    __try
    {
        MmProbeAndLockPages(locked_mdl, UserMode, IoReadAccess);
        pages_locked = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        DbgPrintEx(0, 0, "[hv] MmProbeAndLockPages failed for %p: 0x%X\n",
                 req->VirtualAddress, status);
        goto Exit;
    }

    source_page = MmGetSystemAddressForMdlSafe(
        locked_mdl,
        HighPagePriority | MdlMappingNoExecute);
    if (!source_page)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    pfns = MmGetMdlPfnArray(locked_mdl);
    if (!pfns)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    phys_addr = ((SIZE_T)pfns[0] * PAGE_SIZE) + page_offset;

    if (!ept_hook_page(
            phys_addr,
            source_page,
            page_base,
            target_cr3,
            page_offset,
            req->PatchBytes,
            req->PatchSize,
            locked_mdl,
            PsGetProcessId(target_process),
            target_process))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    locked_mdl = NULL;
    pages_locked = FALSE;
    status = STATUS_SUCCESS;

Exit:
    KeUnstackDetachProcess(&apc_state);

    if (pages_locked)
    {
        MmUnlockPages(locked_mdl);
    }

    if (locked_mdl)
    {
        IoFreeMdl(locked_mdl);
    }

    ObDereferenceObject(target_process);
    return status;
}

static NTSTATUS
DriverHandleEptUnhook(
    _In_ PEPT_HOOK_UNHOOK_REQUEST req)
{
    if (!req || !req->VirtualAddress)
        return STATUS_INVALID_PARAMETER;

    if (!ept_unhook_address((HANDLE)(ULONG_PTR)req->ProcessId, req->VirtualAddress))
        return STATUS_NOT_FOUND;

    return STATUS_SUCCESS;
}

static NTSTATUS
DriverHandleEptUnhookAll(VOID)
{
    SIZE_T removed = ept_unhook_all();
    return removed == 0 ? STATUS_NOT_FOUND : STATUS_SUCCESS;
}

static NTSTATUS
DriverHandleEptUnhookPage(
    _In_ PEPT_HOOK_UNHOOK_REQUEST req)
{
    if (!req || !req->VirtualAddress)
        return STATUS_INVALID_PARAMETER;

    if (!ept_unhook_page((HANDLE)(ULONG_PTR)req->ProcessId, req->VirtualAddress))
        return STATUS_NOT_FOUND;

    return STATUS_SUCCESS;
}

static NTSTATUS
DriverHandleEptSetFastRules(
    _In_ PEPT_HOOK_FAST_RULES_REQUEST req)
{
    if (!req || !req->VirtualAddress || req->RuleCount > EPT_HOOK_MAX_FAST_RULES)
        return STATUS_INVALID_PARAMETER;

    if (!ept_set_fast_rules(
            (HANDLE)(ULONG_PTR)req->ProcessId,
            req->VirtualAddress,
            req->Rules,
            req->RuleCount))
    {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
DriverQueryHookStats(
    _In_ PEPT_HOOK_STATS_QUERY query,
    _Out_ PEPT_HOOK_STATS_RESULT result)
{
    PEPT_HOOK_STATE hook;
    SIZE_T requested_offset;
    PVOID page_base;
    SIZE_T page_pfn = 0;
    NTSTATUS status;

    if (!query || !result || !query->VirtualAddress)
        return STATUS_INVALID_PARAMETER;

    page_base = PAGE_ALIGN(query->VirtualAddress);
    requested_offset = BYTE_OFFSET(query->VirtualAddress);
    hook = DriverFindHookByProcessPage(query->ProcessId, page_base);
    if (!hook)
    {
        status = DriverResolveProcessPagePfn(
            query->ProcessId,
            query->VirtualAddress,
            &page_pfn);
        if (NT_SUCCESS(status))
            hook = DriverFindHookByProcessPfn(query->ProcessId, page_pfn);
    }

    if (!hook)
        return STATUS_NOT_FOUND;

    RtlZeroMemory(result, sizeof(*result));
    result->Size                      = sizeof(*result);
    result->ProcessId                 = query->ProcessId;
    result->RequestedAddress          = (UINT64)(ULONG_PTR)query->VirtualAddress;
    result->TargetPageBase            = (UINT64)(ULONG_PTR)hook->TargetPageBase;
    result->TargetCr3                 = hook->TargetCr3;
    result->OriginalPfn               = hook->OriginalPfn;
    result->FakePfn                   = hook->FakePfn;
    result->PatchOffset               = hook->PatchOffset;
    result->PatchSize                 = hook->PatchSize;
    for (UINT32 i = 0; i < EPT_HOOK_MAX_PATCHES_PER_PAGE; ++i)
    {
        if (hook->Patches[i].Size == 0)
            continue;

        if (hook->Patches[i].Offset == requested_offset)
        {
            result->PatchOffset = hook->Patches[i].Offset;
            result->PatchSize = hook->Patches[i].Size;
            break;
        }
    }
    result->ExecuteViolations         = (UINT64)hook->ExecuteViolationCount;
    result->ReadViolations            = (UINT64)hook->ReadViolationCount;
    result->WriteViolations           = (UINT64)hook->WriteViolationCount;
    result->ContextMismatchViolations = (UINT64)hook->ContextMismatchCount;
    result->MtfCount                  = (UINT64)hook->MtfCount;
    result->EmulationSuccesses        = (UINT64)hook->EmulationSuccessCount;
    result->EmulationFailures         = (UINT64)hook->EmulationFailureCount;
    result->LastViolationRip          = (UINT64)hook->LastViolationRip;
    result->LastGuestPhysical         = (UINT64)hook->LastGuestPhysical;
    result->LastGuestLinear           = (UINT64)hook->LastGuestLinear;
    result->LastViolationFlags        = (UINT32)hook->LastViolationFlags;
    result->Enabled                   = hook->Enabled ? 1U : 0U;
    DriverCopyHookHotspots(hook, result);

    // FF-raw emulation diagnostics
    result->FfRawFailMode       = (UINT64)hook->FfRawFailMode;
    result->FfRawFailInsnRead   = (UINT64)hook->FfRawFailInsnRead;
    result->FfRawFailOpcode     = (UINT64)hook->FfRawFailOpcode;
    result->FfRawFailAddrCalc   = (UINT64)hook->FfRawFailAddrCalc;
    result->FfRawFailTargetRead = (UINT64)hook->FfRawFailTargetRead;
    result->FfRawFailStack      = (UINT64)hook->FfRawFailStack;
    result->FfRawSuccess        = (UINT64)hook->FfRawSuccess;
    result->FfShortcutSuccess   = (UINT64)hook->FfShortcutSuccess;
    result->FfShortcutFail      = (UINT64)hook->FfShortcutFail;

    return STATUS_SUCCESS;
}

static NTSTATUS
DriverIoControl(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
    PIO_STACK_LOCATION io_stack;
    ULONG              ioctl_code;

    UNREFERENCED_PARAMETER(device_obj);

    io_stack = IoGetCurrentIrpStackLocation(irp);
    ioctl_code = io_stack->Parameters.DeviceIoControl.IoControlCode;
    irp->IoStatus.Information = 0;

    switch (ioctl_code)
    {
    case IOCTL_HV_STATUS:
    {
        if (io_stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(UINT32))
        {
            *(UINT32 *)irp->AssociatedIrp.SystemBuffer = g_cpu_count;
            irp->IoStatus.Information = sizeof(UINT32);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_EPT_HOOK:
    {
        ULONG input_len = io_stack->Parameters.DeviceIoControl.InputBufferLength;

        if (input_len >= sizeof(EPT_HOOK_REQUEST))
        {
            PEPT_HOOK_REQUEST req = (PEPT_HOOK_REQUEST)irp->AssociatedIrp.SystemBuffer;
            status = DriverHandleEptHook(req);
        }
        else if (input_len >= sizeof(EPT_HOOK_REQUEST32))
        {
            PEPT_HOOK_REQUEST32 req32 = (PEPT_HOOK_REQUEST32)irp->AssociatedIrp.SystemBuffer;
            EPT_HOOK_REQUEST req = { 0 };

            req.ProcessId      = req32->ProcessId;
            req.VirtualAddress = (PVOID)(ULONG_PTR)req32->VirtualAddress;
            RtlCopyMemory(req.PatchBytes, req32->PatchBytes, sizeof(req.PatchBytes));
            req.PatchSize      = req32->PatchSize;

            DbgPrintEx(0, 0, "[hv] IOCTL_HV_EPT_HOOK: accepted 32-bit request (pid=%u, va=%p, inlen=%lu)\n",
                     req.ProcessId, req.VirtualAddress, input_len);

            status = DriverHandleEptHook(&req);
        }
        else
        {
            DbgPrintEx(0, 0, "[hv] IOCTL_HV_EPT_HOOK: input buffer too small (got=%lu, need=%Iu or %Iu)\n",
                     input_len, sizeof(EPT_HOOK_REQUEST), sizeof(EPT_HOOK_REQUEST32));
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_EPT_QUERY_HOOK_STATS:
    {
        ULONG input_len = io_stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG output_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;
        EPT_HOOK_STATS_QUERY query = { 0 };

        // Accept buffers that fit at least the base struct (without FF-raw diag fields)
        #define EPT_HOOK_STATS_RESULT_BASE_SIZE \
            (ULONG)FIELD_OFFSET(EPT_HOOK_STATS_RESULT, FfRawFailMode)

        if (output_len < EPT_HOOK_STATS_RESULT_BASE_SIZE)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (input_len >= sizeof(EPT_HOOK_STATS_QUERY))
        {
            PEPT_HOOK_STATS_QUERY req = (PEPT_HOOK_STATS_QUERY)irp->AssociatedIrp.SystemBuffer;
            query = *req;
        }
        else if (input_len >= sizeof(EPT_HOOK_STATS_QUERY32))
        {
            PEPT_HOOK_STATS_QUERY32 req32 = (PEPT_HOOK_STATS_QUERY32)irp->AssociatedIrp.SystemBuffer;
            query.ProcessId      = req32->ProcessId;
            query.VirtualAddress = (PVOID)(ULONG_PTR)req32->VirtualAddress;
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = DriverQueryHookStats(
            &query,
            (PEPT_HOOK_STATS_RESULT)irp->AssociatedIrp.SystemBuffer);
        if (NT_SUCCESS(status))
        {
            // Return as many bytes as the caller's buffer can hold
            ULONG actual = output_len < sizeof(EPT_HOOK_STATS_RESULT)
                         ? output_len
                         : (ULONG)sizeof(EPT_HOOK_STATS_RESULT);
            irp->IoStatus.Information = actual;
        }
        break;
    }

    case IOCTL_HV_EPT_UNHOOK:
    {
        ULONG input_len = io_stack->Parameters.DeviceIoControl.InputBufferLength;

        if (input_len >= sizeof(EPT_HOOK_UNHOOK_REQUEST))
        {
            PEPT_HOOK_UNHOOK_REQUEST req = (PEPT_HOOK_UNHOOK_REQUEST)irp->AssociatedIrp.SystemBuffer;
            status = DriverHandleEptUnhook(req);
        }
        else if (input_len >= sizeof(EPT_HOOK_UNHOOK_REQUEST32))
        {
            PEPT_HOOK_UNHOOK_REQUEST32 req32 = (PEPT_HOOK_UNHOOK_REQUEST32)irp->AssociatedIrp.SystemBuffer;
            EPT_HOOK_UNHOOK_REQUEST req = { 0 };

            req.ProcessId      = req32->ProcessId;
            req.VirtualAddress = (PVOID)(ULONG_PTR)req32->VirtualAddress;
            status = DriverHandleEptUnhook(&req);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_EPT_UNHOOK_ALL:
        status = DriverHandleEptUnhookAll();
        break;

    case IOCTL_HV_EPT_UNHOOK_PAGE:
    {
        ULONG input_len = io_stack->Parameters.DeviceIoControl.InputBufferLength;

        if (input_len >= sizeof(EPT_HOOK_UNHOOK_REQUEST))
        {
            PEPT_HOOK_UNHOOK_REQUEST req = (PEPT_HOOK_UNHOOK_REQUEST)irp->AssociatedIrp.SystemBuffer;
            status = DriverHandleEptUnhookPage(req);
        }
        else if (input_len >= sizeof(EPT_HOOK_UNHOOK_REQUEST32))
        {
            PEPT_HOOK_UNHOOK_REQUEST32 req32 = (PEPT_HOOK_UNHOOK_REQUEST32)irp->AssociatedIrp.SystemBuffer;
            EPT_HOOK_UNHOOK_REQUEST req = { 0 };

            req.ProcessId      = req32->ProcessId;
            req.VirtualAddress = (PVOID)(ULONG_PTR)req32->VirtualAddress;
            status = DriverHandleEptUnhookPage(&req);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_EPT_SET_FAST_RULES:
    {
        ULONG input_len = io_stack->Parameters.DeviceIoControl.InputBufferLength;

        if (input_len >= sizeof(EPT_HOOK_FAST_RULES_REQUEST))
        {
            PEPT_HOOK_FAST_RULES_REQUEST req = (PEPT_HOOK_FAST_RULES_REQUEST)irp->AssociatedIrp.SystemBuffer;
            status = DriverHandleEptSetFastRules(req);
        }
        else if (input_len >= sizeof(EPT_HOOK_FAST_RULES_REQUEST32))
        {
            PEPT_HOOK_FAST_RULES_REQUEST32 req32 = (PEPT_HOOK_FAST_RULES_REQUEST32)irp->AssociatedIrp.SystemBuffer;
            EPT_HOOK_FAST_RULES_REQUEST req = { 0 };

            req.ProcessId = req32->ProcessId;
            req.VirtualAddress = (PVOID)(ULONG_PTR)req32->VirtualAddress;
            req.RuleCount = req32->RuleCount;
            req.Reserved = req32->Reserved;
            RtlCopyMemory(req.Rules, req32->Rules, sizeof(req.Rules));
            status = DriverHandleEptSetFastRules(&req);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_EPT_BATCH_BEGIN:
        ept_begin_batch_updates();
        status = STATUS_SUCCESS;
        break;

    case IOCTL_HV_EPT_BATCH_END:
        ept_end_batch_updates();
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
