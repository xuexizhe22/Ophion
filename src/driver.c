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
#define IOCTL_HV_DR_HOOK  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _DR_HOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  TargetAddress;
    PVOID  RedirectAddress;  // Mode 2: If non-NULL, redirect execution here
    UINT8  ModifyRegIdx;     // Mode 1: 0=RAX, 1=RCX... 0xFF=None
    UINT64 ModifyRegVal;     // Mode 1: Value to set the register to
} DR_HOOK_REQUEST, *PDR_HOOK_REQUEST;

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

static HANDLE g_hook_guard_thread = NULL;
static KEVENT g_hook_guard_stop_event;

static NTSTATUS DriverCreateClose(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverIoControl(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverHandleEptHook(_In_ PEPT_HOOK_REQUEST req);
static NTSTATUS DriverPreflightCheck(VOID);
static VOID DriverScanExitedHooks(VOID);
static VOID DriverHookGuardThread(_In_ PVOID start_context);

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

// Safe IPI worker that runs on all cores in VMX Non-Root mode.
// It does not execute privileged instructions directly; it simply
// rings the doorbell (VMCALL) to safely enter VMX Root mode on each core.
static ULONG_PTR
BroadcastVmcallWorker(ULONG_PTR Context)
{
    UNREFERENCED_PARAMETER(Context);
    asm_vmx_vmcall(VMCALL_TEST, 0, 0, 0);
    return 0;
}

static NTSTATUS
DriverHandleDrHook(_In_ PDR_HOOK_REQUEST req)
{
    PEPROCESS target_process = NULL;
    NTSTATUS status;

    if (!req->ProcessId || !req->TargetAddress)
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &target_process);
    if (!NT_SUCCESS(status))
        return status;

    KAPC_STATE apc_state;
    KeStackAttachProcess(target_process, &apc_state);
    UINT64 target_cr3 = __readcr3() & ~0xFFFULL;
    KeUnstackDetachProcess(&apc_state);

    ObDereferenceObject(target_process);

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        g_vcpu[i].dr0_hook_target_rip = (UINT64)req->TargetAddress;
        g_vcpu[i].dr0_hook_redirect_rip = (UINT64)req->RedirectAddress;
        g_vcpu[i].dr0_hook_modify_reg_idx = req->ModifyRegIdx;
        g_vcpu[i].dr0_hook_modify_reg_val = req->ModifyRegVal;
        g_vcpu[i].dr0_hook_target_cr3 = target_cr3;
        g_vcpu[i].dr0_hook_enabled = TRUE;
    }

    // Trigger VMCALL to update DR0 and DR7 inside the VMCS for all cores simultaneously
    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)BroadcastVmcallWorker, 0);

    DbgPrintEx(0, 0, "[hv] DR0 Hook Enabled! Target: %llX, Redirect: %llX, ModReg: %u, Val: %llX\n",
               (UINT64)req->TargetAddress, (UINT64)req->RedirectAddress, req->ModifyRegIdx, req->ModifyRegVal);

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

    case IOCTL_HV_DR_HOOK:
    {
        if (io_stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(DR_HOOK_REQUEST))
        {
            PDR_HOOK_REQUEST req = (PDR_HOOK_REQUEST)irp->AssociatedIrp.SystemBuffer;
            status = DriverHandleDrHook(req);
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

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
