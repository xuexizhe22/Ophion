#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <intrin.h>
#include <winreg.h>
#include <tlhelp32.h>
#include <psapi.h>

#define IOCTL_BASE      0x800
#define IOCTL_HV_EPT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_DR_HOOK  CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EPT_HOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
    UCHAR  PatchBytes[16];
    UINT32 PatchSize;
} EPT_HOOK_REQUEST, *PEPT_HOOK_REQUEST;

typedef struct _DR_HOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  TargetAddress;
    PVOID  RedirectAddress;
    UINT8  ModifyRegIdx;
    UINT64 ModifyRegVal;
} DR_HOOK_REQUEST, *PDR_HOOK_REQUEST;

// 原始函数
int TargetFunction()
{
    printf("[TargetFunction] 执行中! 返回值本该是 1337...\n");
    return 1337;
}

// 目标劫持函数 (Redirect Mode)
void RedirectFunction()
{
    printf("\n[RedirectFunction] 哈哈！你的执行流已经被 DR 硬件断点劫持了！\n");
    printf("[RedirectFunction] 在这里跑完你的代码后，你可以任意跳回原程序！\n\n");
    ExitProcess(0);
}

bool IsVmxSupported() { int cpuInfo[4]; __cpuid(cpuInfo, 1); return (cpuInfo[2] & (1 << 5)) != 0; }
bool IsVbsEnabled() { HKEY hKey; DWORD dwValue = 0, dwSize = 4; if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) { if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity", NULL, NULL, (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS) { RegCloseKey(hKey); return dwValue == 1; } RegCloseKey(hKey); } return false; }
bool TryDisableVbs() { printf("[*] 正在尝试为您自动关闭 VBS / Hyper-V...\n"); HKEY hKey; DWORD dwValue = 0; if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) { RegSetValueExA(hKey, "EnableVirtualizationBasedSecurity", 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(dwValue)); RegCloseKey(hKey); } system("bcdedit /set hypervisorlaunchtype off > nul 2>&1"); system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LsaCfgFlags /t REG_DWORD /d 0 /f > nul 2>&1"); printf("[!] 已经执行关闭指令！请立刻重启电脑。\n"); return true; }
bool IsVMwareRunning() { HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); if (hSnapshot != INVALID_HANDLE_VALUE) { PROCESSENTRY32 pe32; pe32.dwSize = sizeof(PROCESSENTRY32); if (Process32First(hSnapshot, &pe32)) { do { if (_stricmp(pe32.szExeFile, "vmware-vmx.exe") == 0) { CloseHandle(hSnapshot); return true; } } while (Process32Next(hSnapshot, &pe32)); } CloseHandle(hSnapshot); } LPVOID drivers[1024]; DWORD cbNeeded; if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) { int cDrivers = cbNeeded / sizeof(LPVOID); for (int i = 0; i < cDrivers; i++) { char szDriver[256]; if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver))) { if (_stricmp(szDriver, "vmx86.sys") == 0) return true; } } } return false; }

int main()
{
    SetConsoleOutputCP(65001);
    printf("--- Ophion 终极挂钩框架 (DR Hook / EPT Hook) 测试工具 ---\n\n");

    if (!IsVmxSupported()) { printf("[-] CPU 不支持 VT-x。\n"); system("pause"); return 1; }
    if (IsVbsEnabled()) { TryDisableVbs(); system("pause"); return 1; }
    if (IsVMwareRunning()) { printf("[-] 检测到 VMware，防蓝屏机制已拒绝加载。\n"); system("pause"); return 1; }

    HANDLE hDevice = CreateFileA("\\\\.\\Ophion", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[-] 连接失败！请加载驱动: sc create Ophion type= kernel binPath= C:\\Ophion.sys && sc start Ophion\n");
        system("pause"); return 1;
    }

    printf("[1] 模式一: DR 硬件断点 (原位寄存器篡改，无缝解决脏页Ping-Pong)\n");
    printf("[2] 模式二: DR 硬件断点 (执行流 RIP 劫持)\n");
    printf("[3] 模式三: EPT Stealth Hook (传统的 EPT 读写分离隐身钩子)\n");
    printf("\n请选择您要测试的挂钩模式 (1-3): ");

    int mode = 0;
    std::cin >> mode;

    DWORD bytesReturned = 0;

    if (mode == 1 || mode == 2)
    {
        DR_HOOK_REQUEST dr_req = { 0 };
        dr_req.ProcessId = GetCurrentProcessId();

        // 我们在这个函数内部下断点，测试能否修改它的返回值或者把它跳走
        dr_req.TargetAddress = (PVOID)((UINT_PTR)&TargetFunction + 0);

        if (mode == 2)
        {
            dr_req.RedirectAddress = (PVOID)&RedirectFunction;
            dr_req.ModifyRegIdx = 0xFF; // 0xFF = 不修改寄存器
        }
        else
        {
            dr_req.RedirectAddress = NULL;
            dr_req.ModifyRegIdx = 0; // 0 = RAX 寄存器
            dr_req.ModifyRegVal = 9999;
        }

        printf("\n[+] 发送 DR Hook 请求... Target = %p\n", dr_req.TargetAddress);
        if (DeviceIoControl(hDevice, IOCTL_HV_DR_HOOK, &dr_req, sizeof(dr_req), NULL, 0, &bytesReturned, NULL))
        {
            printf("[+] DR 硬件隐形 Hook 安装成功！准备调用 TargetFunction()...\n\n");

            // 此时调用 TargetFunction，它的执行流刚开始就会踩到 DR0 硬件断点
            int result = TargetFunction();

            if (mode == 1)
            {
                printf("\n[+] DR 寄存器篡改成功！返回结果被内核偷偷改成了: %d (预期: 9999)\n", result);
                printf("[+] 注意：这个过程没有修改 EPT，没有任何 Ping-Pong 效应，游戏帧率满血！\n");
            }
        }
        else
            printf("[-] DR Hook 安装失败！\n");
    }
    else if (mode == 3)
    {
        EPT_HOOK_REQUEST ept_req = { 0 };
        ept_req.ProcessId = GetCurrentProcessId();
        ept_req.VirtualAddress = (PVOID)&TargetFunction;
        UCHAR patch[] = { 0xB8, 0x0F, 0x27, 0x00, 0x00, 0xC3 }; // mov eax, 9999; ret
        memcpy(ept_req.PatchBytes, patch, sizeof(patch));
        ept_req.PatchSize = sizeof(patch);

        if (DeviceIoControl(hDevice, IOCTL_HV_EPT_HOOK, &ept_req, sizeof(ept_req), NULL, 0, &bytesReturned, NULL))
        {
            printf("[+] EPT Hook 应用成功！\n");
            int result = TargetFunction();
            printf("[+] EPT 拦截返回结果: %d (预期: 9999)\n", result);
        }
        else
            printf("[-] EPT Hook 失败！\n");
    }

    CloseHandle(hDevice);
    system("pause");
    return 0;
}
