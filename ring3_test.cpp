#include <windows.h>
#include <stdio.h>
#include <iostream>

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

int main()
{
    printf("[+] TargetFunction address: %p\n", &TargetFunction);

    // 执行原始函数并输出结果
    int result1 = TargetFunction();
    printf("[+] Original result: %d\n", result1);

    // 构造请求，将返回值修改为 9999 (0x270F)
    // 原始汇编可能是 mov eax, 1337 (B8 39 05 00 00)
    // 补丁汇编为 mov eax, 9999 (B8 0F 27 00 00)

    EPT_HOOK_REQUEST req = { 0 };
    req.ProcessId = GetCurrentProcessId();
    req.VirtualAddress = (PVOID)&TargetFunction;

    // X64 可能会有 padding 或不同的汇编，但我们为了测试简单覆盖前几个字节为 mov eax, 9999; ret
    // 补丁: B8 0F 27 00 00 C3 (mov eax, 0x270F; ret)
    UCHAR patch[] = { 0xB8, 0x0F, 0x27, 0x00, 0x00, 0xC3 };
    memcpy(req.PatchBytes, patch, sizeof(patch));
    req.PatchSize = sizeof(patch);

    HANDLE hDevice = CreateFileA("\\\\.\\Ophion", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open handle to hypervisor driver. Make sure the driver is loaded.\n");
        return 1;
    }

    printf("[+] Sending IOCTL to hook EPT...\n");
    DWORD bytesReturned = 0;
    BOOL bResult = DeviceIoControl(hDevice, IOCTL_HV_EPT_HOOK, &req, sizeof(req), NULL, 0, &bytesReturned, NULL);

    if (bResult)
    {
        printf("[+] EPT Hook applied successfully!\n");

        // 再次执行该函数
        int result2 = TargetFunction();
        printf("[+] Result after EPT Hook: %d (Expected: 9999)\n", result2);

        // 尝试通过内存读取查看该内存页面的内容（应该是未被修改的原始值）
        UCHAR memoryContent[6];
        memcpy(memoryContent, (PVOID)&TargetFunction, sizeof(memoryContent));

        printf("[+] Memory bytes at TargetFunction: ");
        for (int i = 0; i < sizeof(memoryContent); i++)
        {
            printf("%02X ", memoryContent[i]);
        }
        printf("\n");

        if (memcmp(memoryContent, patch, sizeof(patch)) != 0)
        {
            printf("[+] EPT Hook stealth validation passed! Memory appears unchanged from Ring 3.\n");
        }
        else
        {
            printf("[-] EPT Hook stealth validation failed. Memory changes are visible.\n");
        }
    }
    else
    {
        printf("[-] DeviceIoControl failed.\n");
    }

    CloseHandle(hDevice);
    return 0;
}