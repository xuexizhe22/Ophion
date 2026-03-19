/*
*   broadcast.c - dpc-based broadcast for multi-processor vmx operations
*   uses KeGenericCallDpc to execute code on all logical processors
*/
#include "hv.h"

// KeGenericCallDpc, KeSignalCallDpcDone, KeSignalCallDpcSynchronize
// are not in the standard wdk headers
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID          Context);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2);

static VOID
dpc_init_guest(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    // saves gprs + rflags, calls vmx_virtualize_cpu(rsp)
    // on successful vmlaunch, returns via asm_vmx_restore_state
    asm_vmx_save_state();

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID
dpc_terminate_guest(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    asm_vmx_vmcall(VMCALL_VMXOFF, 0, 0, 0);

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

VOID
broadcast_virtualize_all(VOID)
{
    KeGenericCallDpc(dpc_init_guest, NULL);
}

VOID
broadcast_terminate_all(VOID)
{
    KeGenericCallDpc(dpc_terminate_guest, NULL);
}
