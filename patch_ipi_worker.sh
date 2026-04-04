#!/bin/bash
cat << 'INNER_EOF' > src/driver.c.patch
--- src/driver.c
+++ src/driver.c
@@ -391,6 +391,15 @@
     ObDereferenceObject(target_process);
     return status;
 }
+
+// Safe IPI worker that runs on all cores in VMX Non-Root mode.
+// It does not execute privileged instructions directly; it simply
+// rings the doorbell (VMCALL) to safely enter VMX Root mode on each core.
+static ULONG_PTR
+BroadcastVmcallWorker(ULONG_PTR Context)
+{
+    UNREFERENCED_PARAMETER(Context);
+    asm_vmx_vmcall(VMCALL_TEST, 0, 0, 0);
+    return 0;
+}

 static NTSTATUS
 DriverHandleDrHook(_In_ PDR_HOOK_REQUEST req)
@@ -423,7 +432,7 @@
     }

     // Trigger VMCALL to update DR0 and DR7 inside the VMCS for all cores simultaneously
-    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)ept_invept_all, 0);
+    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)BroadcastVmcallWorker, 0);

     DbgPrintEx(0, 0, "[hv] DR0 Hook Enabled! Target: %llX, Redirect: %llX, ModReg: %u, Val: %llX\n",
                (UINT64)req->TargetAddress, (UINT64)req->RedirectAddress, req->ModifyRegIdx, req->ModifyRegVal);
INNER_EOF
patch -p0 < src/driver.c.patch
