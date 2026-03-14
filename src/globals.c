/*
*   globals.c - global variable definitions
*/
#include "hv.h"

VIRTUAL_MACHINE_STATE *g_vcpu               = NULL;
EPT_STATE *g_ept                            = NULL;
UINT32 g_cpu_count                          = 0;

// stable system process CR3 captured before virtualization
UINT64 g_system_cr3                         = 0;

// bitmap of msrs that cause #gp on bare metal (probed at init time)
UINT64 *g_msr_bitmap_invalid                = NULL;

BOOLEAN g_stealth_enabled                   = STEALTH_ENABLED;
STEALTH_CPUID_CACHE g_stealth_cpuid_cache   = {0};
