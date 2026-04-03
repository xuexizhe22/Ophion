#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <intrin.h>
#include <winreg.h>
#include <tlhelp32.h>
#include <psapi.h>

#define IOCTL_BASE      0x800
#define IOCTL_HV_EPT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EPT_HOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
    UCHAR  PatchBytes[16];
    UINT32 PatchSize;
} EPT_HOOK_REQUEST, *PEPT_HOOK_REQUEST;

// 原始函数 - 返回 1337
int TargetFunction()
{
    return 1337;
}

// 检查 CPU 是否支持 VT-x
bool IsVmxSupported()
{
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 5)) != 0;
}

// 检查 VBS/核心隔离是否开启
bool IsVbsEnabled()
{
    HKEY hKey;
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(dwValue);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExA(hKey, "EnableVirtualizationBasedSecurity", NULL, NULL, (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            if (dwValue == 1) return true;
        }
        RegCloseKey(hKey);
    }
    return false;
}

// 尝试关闭 VBS 并提示重启
bool TryDisableVbs()
{
    printf("[!] 检测到 Windows 开启了 VBS (基于虚拟化的安全) / 核心隔离 / Hyper-V。\n");
    printf("[!] 这会导致 Ophion 驱动抢占 VT-x 失败并引发蓝屏。\n\n");
    printf("[*] 正在尝试为您自动关闭 VBS / Hyper-V...\n");

    HKEY hKey;
    DWORD dwValue = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        RegSetValueExA(hKey, "EnableVirtualizationBasedSecurity", 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(dwValue));
        RegCloseKey(hKey);
    }

    system("bcdedit /set hypervisorlaunchtype off > nul 2>&1");
    system("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LsaCfgFlags /t REG_DWORD /d 0 /f > nul 2>&1");

    printf("\n======================================================\n");
    printf("[!] 已经为您执行了关闭指令！\n");
    printf("[!] 请立刻重启电脑，然后再次运行本程序。\n");
    printf("======================================================\n");
    return true;
}

// 检查 VMware 是否在运行
bool IsVMwareRunning()
{
    // 1. 检查是否存在 vmware-vmx.exe 进程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32))
        {
            do {
                if (_stricmp(pe32.szExeFile, "vmware-vmx.exe") == 0)
                {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // 2. 检查驱动 vmx86.sys 是否已加载
    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
    {
        int cDrivers = cbNeeded / sizeof(LPVOID);
        for (int i = 0; i < cDrivers; i++)
        {
            char szDriver[256];
            if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver)))
            {
                if (_stricmp(szDriver, "vmx86.sys") == 0)
                    return true;
            }
        }
    }
    return false;
}

int main()
{
    SetConsoleOutputCP(65001);
    printf("--- Ophion EPT Stealth Hook 测试工具 ---\n\n");

    printf("[*] 正在进行环境自检...\n");

    if (!IsVmxSupported())
    {
        printf("[-] 致命错误：您的 CPU 不支持 Intel VT-x 硬件虚拟化！程序无法运行。\n");
        system("pause");
        return 1;
    }
    printf("[+] CPU 支持 Intel VT-x。\n");

    if (IsVbsEnabled())
    {
        TryDisableVbs();
        system("pause");
        return 1;
    }
    printf("[+] VBS 核心隔离已处于关闭状态。\n");

    if (IsVMwareRunning())
    {
        printf("\n[-] 检测到 VMware 虚拟机正在运行 (vmx86.sys 或 vmware-vmx.exe 活跃中)！\n");
        printf("[!] 强行加载 Ophion 会导致 VT-x 硬件抢占，直接触发蓝屏！\n");
        printf("[!] 请先完全关闭所有 VMware 虚拟机后再运行本程序。\n\n");
        system("pause");
        return 1;
    }
    printf("[+] 未检测到冲突的虚拟机软件。\n\n");

    printf("[+] TargetFunction 内存地址: %p\n", &TargetFunction);
    int result1 = TargetFunction();
    printf("[+] 原始函数返回结果: %d\n", result1);

    EPT_HOOK_REQUEST req = { 0 };
    req.ProcessId = GetCurrentProcessId();
    req.VirtualAddress = (PVOID)&TargetFunction;

    UCHAR patch[] = { 0xB8, 0x0F, 0x27, 0x00, 0x00, 0xC3 };
    memcpy(req.PatchBytes, patch, sizeof(patch));
    req.PatchSize = sizeof(patch);

    printf("[*] 正在尝试连接 Ophion 驱动层...\n");
    HANDLE hDevice = CreateFileA("\\\\.\\Ophion", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[-] 连接失败！请确保您已经加载了 Ophion.sys 驱动。\n");
        printf("    (加载命令: sc create Ophion type= kernel binPath= C:\\Ophion.sys && sc start Ophion)\n");
        system("pause");
        return 1;
    }

    printf("[+] 连接驱动成功，正在发送 EPT Hook 指令...\n");
    DWORD bytesReturned = 0;
    BOOL bResult = DeviceIoControl(hDevice, IOCTL_HV_EPT_HOOK, &req, sizeof(req), NULL, 0, &bytesReturned, NULL);

    if (bResult)
    {
        printf("[+] EPT Hook 应用成功！\n");
        int result2 = TargetFunction();
        printf("[+] Hook 后的返回结果: %d (预期应为: 9999)\n", result2);

        UCHAR memoryContent[6];
        memcpy(memoryContent, (PVOID)&TargetFunction, sizeof(memoryContent));

        printf("[+] 当前内存中的真实字节: ");
        for (int i = 0; i < sizeof(memoryContent); i++)
        {
            printf("%02X ", memoryContent[i]);
        }
        printf("\n");

        if (memcmp(memoryContent, patch, sizeof(patch)) != 0)
            printf("[+] 完美！EPT Hook 无痕检测通过！\n");
        else
            printf("[-] 警告：EPT Hook 可能失败，内存已经被物理修改。\n");
    }
    else
    {
        printf("[-] DeviceIoControl 发送指令失败。\n");
    }

    CloseHandle(hDevice);
    system("pause");
    return 0;
}
