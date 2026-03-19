/*
*   driver.c - windows kernel driver entry point for the hypervisor
*   creates a device object, symbolic link, and initializes vmx
*   provides ioctl interface for usermode loader communication
*/
#include "hv.h"
#include <ntifs.h>

#define DEVICE_NAME     L"\\Device\\Ophion"
#define SYMLINK_NAME    L"\\DosDevices\\Ophion"

#define IOCTL_BASE      0x800
#define IOCTL_HV_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EPT_HOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
    UCHAR  PatchBytes[16];
    UINT32 PatchSize;
} EPT_HOOK_REQUEST, *PEPT_HOOK_REQUEST;

static NTSTATUS DriverCreateClose(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverIoControl(PDEVICE_OBJECT device_obj, PIRP irp);

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNICODE_STRING symlink;

    DbgPrintEx(0, 0, "[hv] Unloading hypervisor driver...\n");

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

    DbgPrintEx(0, 0, "[hv] DriverEntry — Hypervisor initializing...\n");

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
        vmx_terminate();  // clean up any partially-allocated resources
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(device_obj);
        return STATUS_HV_OPERATION_FAILED;
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
DriverIoControl(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
    PIO_STACK_LOCATION io_stack;
    ULONG              ioctl_code;

    UNREFERENCED_PARAMETER(device_obj);

    io_stack       = IoGetCurrentIrpStackLocation(irp);
    ioctl_code = io_stack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioctl_code)
    {
    case IOCTL_HV_STATUS:
    {
        //
        // return basic status: number of virtualized cores
        //
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
        if (io_stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(EPT_HOOK_REQUEST))
        {
            PEPT_HOOK_REQUEST req = (PEPT_HOOK_REQUEST)irp->AssociatedIrp.SystemBuffer;
            PEPROCESS target_process = NULL;

            // Validate that the patch won't overflow a page boundary
            SIZE_T offset = (SIZE_T)req->VirtualAddress & (PAGE_SIZE - 1);
            if (offset + req->PatchSize > PAGE_SIZE || req->PatchSize > sizeof(req->PatchBytes))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->ProcessId, &target_process);
            if (NT_SUCCESS(status))
            {
                KAPC_STATE apc_state;
                KeStackAttachProcess(target_process, &apc_state);

                // Lock the page in memory so it isn't paged out while hooked
                PMDL mdl = IoAllocateMdl(req->VirtualAddress, req->PatchSize, FALSE, FALSE, NULL);
                if (mdl)
                {
                    __try
                    {
                        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);

                        PHYSICAL_ADDRESS phys_addr = MmGetPhysicalAddress(req->VirtualAddress);

                        if (phys_addr.QuadPart != 0)
                        {
                            if (ept_hook_page(phys_addr.QuadPart, req->PatchBytes, req->PatchSize))
                            {
                                status = STATUS_SUCCESS;
                            }
                            else
                            {
                                MmUnlockPages(mdl);
                                IoFreeMdl(mdl);
                                status = STATUS_UNSUCCESSFUL;
                            }
                        }
                        else
                        {
                            MmUnlockPages(mdl);
                            IoFreeMdl(mdl);
                            status = STATUS_INVALID_ADDRESS;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        IoFreeMdl(mdl);
                        status = GetExceptionCode();
                    }
                }
                else
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                }

                KeUnstackDetachProcess(&apc_state);
                ObDereferenceObject(target_process);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    default:
        //
        // add more shi here later
        //
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
