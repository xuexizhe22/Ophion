#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <intrin.h>
#include <stdio.h>
#include <stdint.h>
#include <algorithm>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#ifndef PF_HYPERVISOR_PRESENT
#define PF_HYPERVISOR_PRESENT 27
#endif

#define IOCTL_BASE 0x800
#define IOCTL_HV_EPT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_QUERY_HOOK_STATS CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_BATCH_BEGIN CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_BATCH_END CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_UNHOOK CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_UNHOOK_ALL CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_UNHOOK_PAGE CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_EPT_SET_FAST_RULES CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define EPT_HOOK_HOTSPOT_COUNT 8
#define EPT_HOOK_MAX_FAST_RULES 8

typedef struct _EPT_HOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
    UCHAR  PatchBytes[16];
    UINT32 PatchSize;
} EPT_HOOK_REQUEST, *PEPT_HOOK_REQUEST;

typedef struct _EPT_HOOK_STATS_QUERY {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
} EPT_HOOK_STATS_QUERY, *PEPT_HOOK_STATS_QUERY;

typedef struct _EPT_HOOK_UNHOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
} EPT_HOOK_UNHOOK_REQUEST, *PEPT_HOOK_UNHOOK_REQUEST;

typedef enum _EPT_HOOK_FAST_RULE_TYPE {
    EptHookFastRuleNone = 0,
    EptHookFastRuleLookupMovzx = 1,
    EptHookFastRuleLookupMovsx = 2,
    EptHookFastRuleLookupMov = 3,
    EptHookFastRuleFfJmp = 4,
    EptHookFastRuleFfCall = 5
} EPT_HOOK_FAST_RULE_TYPE;

typedef struct _EPT_HOOK_FAST_RULE {
    UINT16 RipOffset;
    UINT16 GlaOffsetStart;
    UINT16 GlaOffsetEnd;
    UINT8  Type;
    UINT8  DestReg;
    UINT8  DataSize;
    UINT8  InsnLength;
    UINT8  Opcode[4];
    UINT8  OpcodeLength;
    UINT8  Reserved[3];
} EPT_HOOK_FAST_RULE, *PEPT_HOOK_FAST_RULE;

typedef struct _EPT_HOOK_FAST_RULES_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
    UINT32 RuleCount;
    UINT32 Reserved;
    EPT_HOOK_FAST_RULE Rules[EPT_HOOK_MAX_FAST_RULES];
} EPT_HOOK_FAST_RULES_REQUEST, *PEPT_HOOK_FAST_RULES_REQUEST;

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

#define HV_HOOK_FAULT_FLAG_EXECUTE        0x00000001U
#define HV_HOOK_FAULT_FLAG_READ           0x00000002U
#define HV_HOOK_FAULT_FLAG_WRITE          0x00000004U
#define HV_HOOK_FAULT_FLAG_LINEAR_VALID   0x00000008U
#define HV_HOOK_FAULT_FLAG_CONTEXT_MATCH  0x00000010U

struct HookSpec
{
    UINT64 Address;
    std::vector<UCHAR> PatchBytes;
    std::string SourceAddressText;
    std::string ResolvedAddressText;
};

struct TargetContext
{
    DWORD ProcessId;
    UINT64 GameDllBase;
    std::string ImageName;
};

struct PageRiskFinding
{
    UINT64 Address;
    UINT64 RelatedAddress;
    std::string Category;
    std::string Detail;
};

struct PagePreflightReport
{
    UINT64 RequestedAddress;
    UINT64 PageBase;
    bool IsWow64;
    bool ReadSucceeded;
    std::vector<PageRiskFinding> Findings;
};

struct HookOverlapWarning
{
    size_t FirstIndex;
    size_t SecondIndex;
    UINT64 PageBase;
    UINT64 FirstStart;
    UINT64 FirstEnd;
    UINT64 SecondStart;
    UINT64 SecondEnd;
};

struct SessionInstalledHook
{
    DWORD ProcessId;
    UINT64 Address;
    std::string SourceAddressText;
    std::string ResolvedAddressText;
};

struct VirtualizationConflictProcess
{
    DWORD ProcessId;
    std::string ImageName;
};

static const char* kDriverServiceName = "Ophion";
static const char* kDriverDisplayName = "Ophion Hypervisor";
static const char* kDevicePath = "\\\\.\\Ophion";
static const wchar_t* kPreferredTargetNames[] = { L"war3.exe", L"16_war3.exe" };
static const wchar_t* kDefaultModuleName = L"game.dll";
static const UINT64 kLegacyGameDllBase = 0x6F000000ULL;
static const SIZE_T kPageBytes = 0x1000;
static const UINT64 kLargePageBytes = 0x200000ULL;
static std::vector<SessionInstalledHook> g_session_installed_hooks;

static bool TryGetModuleBase(DWORD pid, const wchar_t* module_name, UINT64* base_address, std::string* resolved_name);
static std::string FormatGameDllAddress(UINT64 game_dll_base, UINT64 address);
static bool SendSimpleIoctlHandle(HANDLE device, DWORD ioctl_code);
static bool SendFastRulesHandle(HANDLE device, const EPT_HOOK_FAST_RULES_REQUEST* req);
static void PrintHookStatsResult(const TargetContext& target, const std::string& resolved_text, const EPT_HOOK_STATS_RESULT& result);
static void StripExeToken(std::vector<std::string>* tokens);
static std::string WideToAnsi(const wchar_t* text);


static std::string ToLowerAscii(const std::string& value)
{
    std::string lowered = value;
    for (size_t i = 0; i < lowered.size(); ++i)
    {
        if (lowered[i] >= 'A' && lowered[i] <= 'Z')
            lowered[i] = static_cast<char>(lowered[i] - 'A' + 'a');
    }

    return lowered;
}

static bool EndsWithInsensitive(const std::string& value, const std::string& suffix)
{
    if (value.size() < suffix.size())
        return false;

    return ToLowerAscii(value.substr(value.size() - suffix.size())) == ToLowerAscii(suffix);
}

static bool StartsWithInsensitive(const std::string& value, const std::string& prefix)
{
    if (value.size() < prefix.size())
        return false;

    return ToLowerAscii(value.substr(0, prefix.size())) == ToLowerAscii(prefix);
}

static bool FileExists(const std::string& path)
{
    DWORD attributes = GetFileAttributesA(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static std::string ParentPath(const std::string& path)
{
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos)
        return std::string();

    return path.substr(0, pos);
}

static std::string JoinPath(const std::string& base, const std::string& child)
{
    if (base.empty())
        return child;

    if (base.back() == '\\' || base.back() == '/')
        return base + child;

    return base + "\\" + child;
}

static std::string GetExecutablePath()
{
    char buffer[4096] = { 0 };
    DWORD length = GetModuleFileNameA(NULL, buffer, static_cast<DWORD>(sizeof(buffer)));
    if (length == 0 || length >= sizeof(buffer))
        return std::string();

    return std::string(buffer, length);
}

static std::vector<std::string> GetDriverPathCandidates()
{
    std::vector<std::string> candidates;
    std::string exe_path = GetExecutablePath();
    std::string exe_dir = ParentPath(exe_path);
    std::string root_dir = ParentPath(ParentPath(ParentPath(exe_dir)));

    if (!exe_dir.empty())
    {
        candidates.push_back(JoinPath(exe_dir, "Ophion.sys"));
    }

    if (!root_dir.empty())
    {
        candidates.push_back(JoinPath(root_dir, "Ophion-master\\build\\bin\\Debug\\Ophion.sys"));
        candidates.push_back(JoinPath(root_dir, "Ophion-master\\build\\bin\\Debug_preflight\\Ophion.sys"));
        candidates.push_back(JoinPath(root_dir, "Ophion-master\\build\\bin\\Release\\Ophion.sys"));
    }

    char current_dir[4096] = { 0 };
    DWORD cwd_length = GetCurrentDirectoryA(static_cast<DWORD>(sizeof(current_dir)), current_dir);
    if (cwd_length > 0 && cwd_length < sizeof(current_dir))
    {
        candidates.push_back(JoinPath(current_dir, "Ophion.sys"));
    }

    return candidates;
}

static bool ResolveDriverPath(std::string* path)
{
    if (!path)
        return false;

    std::vector<std::string> candidates = GetDriverPathCandidates();
    for (size_t i = 0; i < candidates.size(); ++i)
    {
        if (FileExists(candidates[i]))
        {
            *path = candidates[i];
            return true;
        }
    }

    return false;
}

static HANDLE TryOpenDriverHandle()
{
    return CreateFileA(
        kDevicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
}

static void PrintLastError(const char* prefix, DWORD error)
{
    char* message = NULL;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD length = FormatMessageA(flags, NULL, error, 0, (LPSTR)&message, 0, NULL);

    if (length != 0 && message)
    {
        while (length > 0 && (message[length - 1] == '\r' || message[length - 1] == '\n'))
        {
            message[length - 1] = '\0';
            --length;
        }

        printf("%s%lu (%s)\n", prefix, error, message);
        LocalFree(message);
        return;
    }

    printf("%s%lu\n", prefix, error);
}

static bool EnablePrivilege(const wchar_t* privilege_name)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges = { 0 };
    LUID luid = { 0 };
    BOOL ok = FALSE;
    DWORD error = ERROR_SUCCESS;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    if (!LookupPrivilegeValueW(NULL, privilege_name, &luid))
    {
        CloseHandle(token);
        return false;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    ok = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL);
    error = GetLastError();
    CloseHandle(token);

    if (!ok || error == ERROR_NOT_ALL_ASSIGNED)
        return false;

    return true;
}

static const char* ServiceStateToText(DWORD state)
{
    switch (state)
    {
    case SERVICE_STOPPED:
        return "\u5df2\u505c\u6b62";
    case SERVICE_START_PENDING:
        return "\u6b63\u5728\u542f\u52a8";
    case SERVICE_STOP_PENDING:
        return "\u6b63\u5728\u505c\u6b62";
    case SERVICE_RUNNING:
        return "\u8fd0\u884c\u4e2d";
    case SERVICE_CONTINUE_PENDING:
        return "\u6b63\u5728\u7ee7\u7eed";
    case SERVICE_PAUSE_PENDING:
        return "\u6b63\u5728\u6682\u505c";
    case SERVICE_PAUSED:
        return "\u5df2\u6682\u505c";
    default:
        return "\u672a\u77e5";
    }
}

static bool WaitForDriverDevice(DWORD timeout_ms)
{
    DWORD waited = 0;

    while (waited <= timeout_ms)
    {
        HANDLE device = TryOpenDriverHandle();
        if (device != INVALID_HANDLE_VALUE)
        {
            CloseHandle(device);
            return true;
        }

        Sleep(200);
        waited += 200;
    }

    return false;
}

static bool WaitForDriverDeviceGone(DWORD timeout_ms)
{
    DWORD waited = 0;

    while (waited <= timeout_ms)
    {
        HANDLE device = TryOpenDriverHandle();
        if (device == INVALID_HANDLE_VALUE)
            return true;

        CloseHandle(device);
        Sleep(200);
        waited += 200;
    }

    return false;
}

static bool IsVirtualizationConflictProcessName(const std::string& image_name)
{
    const std::string lowered = ToLowerAscii(image_name);

    //
    // 只拦“真正正在运行虚拟机”的宿主进程，不拦管理器/后台常驻程序。
    // 例如：
    //   - vmware.exe / vmplayer.exe 只是管理界面，不一定有虚拟机在跑
    //   - VirtualBox.exe 也是管理器
    //   - vmcompute/vmmem 可能只是 WSL/Docker 后台，不代表当前一定会与我们冲突
    //
    if (lowered == "vmware-vmx.exe" ||
        lowered == "virtualboxvm.exe" ||
        lowered == "vboxheadless.exe" ||
        lowered == "vmwp.exe")
    {
        return true;
    }

    if (StartsWithInsensitive(lowered, "qemu-system-"))
        return true;

    return false;
}

static bool CollectVirtualizationConflictProcesses(std::vector<VirtualizationConflictProcess>* conflicts)
{
    if (!conflicts)
        return false;

    conflicts->clear();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            std::string image_name = WideToAnsi(entry.szExeFile);
            if (!image_name.empty() && IsVirtualizationConflictProcessName(image_name))
            {
                VirtualizationConflictProcess process = {};
                process.ProcessId = entry.th32ProcessID;
                process.ImageName = image_name;
                conflicts->push_back(process);
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return !conflicts->empty();
}

static bool DetectSystemHypervisor(std::string* vendor_name)
{
    int cpu_info[4] = { 0 };
    bool cpuid_hypervisor_present = false;

    if (vendor_name)
        vendor_name->clear();

    __cpuid(cpu_info, 1);
    cpuid_hypervisor_present = ((static_cast<unsigned int>(cpu_info[2]) >> 31) & 0x1U) != 0;

    if (!cpuid_hypervisor_present && !IsProcessorFeaturePresent(PF_HYPERVISOR_PRESENT))
        return false;

    if (vendor_name)
    {
        char vendor[13] = { 0 };
        __cpuid(cpu_info, 0x40000000);
        memcpy(&vendor[0], &cpu_info[1], sizeof(int));
        memcpy(&vendor[4], &cpu_info[2], sizeof(int));
        memcpy(&vendor[8], &cpu_info[3], sizeof(int));
        vendor[12] = '\0';

        *vendor_name = vendor[0] != '\0' ? vendor : "unknown";
    }

    return true;
}

static bool CheckVirtualizationConflictBeforeLoad()
{
    std::string hypervisor_vendor;
    std::vector<VirtualizationConflictProcess> conflicts;

    if (DetectSystemHypervisor(&hypervisor_vendor))
    {
        printf("[-] 检测到当前系统已经存在 hypervisor 环境，已阻止启动 Ophion：%s\n",
            hypervisor_vendor.empty() ? "unknown" : hypervisor_vendor.c_str());
        printf("[!] 这通常表示你当前就在虚拟机里，或者物理机启用了 Hyper-V / VBS / 内存完整性。\n");
        return false;
    }

    if (!CollectVirtualizationConflictProcesses(&conflicts))
        return true;

    printf("[-] 检测到正在运行的虚拟机宿主进程，已阻止启动 Ophion 以避免物理机触发 VMX/VMX86 蓝屏：\n");
    for (size_t i = 0; i < conflicts.size(); ++i)
    {
        printf("    PID=%lu  %s\n",
            conflicts[i].ProcessId,
            conflicts[i].ImageName.c_str());
    }

    printf("[!] 请先关闭正在运行的虚拟机实例后，再重新执行。\n");
    return false;
}

static bool EnsureDriverLoaded()
{
    HANDLE existing_device = TryOpenDriverHandle();
    if (existing_device != INVALID_HANDLE_VALUE)
    {
        printf("[+] \u9a71\u52a8\u5df2\u7ecf\u52a0\u8f7d\uff0c\u8bbe\u5907\u5df2\u5c31\u7eea: %s\n", kDevicePath);
        CloseHandle(existing_device);
        return true;
    }

   /// if (!CheckVirtualizationConflictBeforeLoad())//关闭虚拟机检测
    ///    return false;

    std::string driver_path;
    if (!ResolveDriverPath(&driver_path))
    {
        printf("[-] \u65e0\u6cd5\u81ea\u52a8\u627e\u5230 Ophion.sys\u3002\n");
        return false;
    }

    printf("[*] \u9a71\u52a8\u8def\u5f84: %s\n", driver_path.c_str());

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm)
    {
        PrintLastError("[-] \u6253\u5f00\u670d\u52a1\u7ba1\u7406\u5668\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
        printf("[!] \u8bf7\u4f7f\u7528\u7ba1\u7406\u5458\u6743\u9650\u8fd0\u884c\u672c\u7a0b\u5e8f\u3002\n");
        return false;
    }

    SC_HANDLE service = OpenServiceA(
        scm,
        kDriverServiceName,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);

    if (!service)
    {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_DOES_NOT_EXIST)
        {
            PrintLastError("[-] \u6253\u5f00\u9a71\u52a8\u670d\u52a1\u5931\u8d25\uff0c\u9519\u8bef\u7801=", error);
            CloseServiceHandle(scm);
            return false;
        }

        service = CreateServiceA(
            scm,
            kDriverServiceName,
            kDriverDisplayName,
            SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driver_path.c_str(),
            NULL,
            NULL,
            NULL,
            NULL,
            NULL);

        if (!service)
        {
            PrintLastError("[-] \u521b\u5efa\u9a71\u52a8\u670d\u52a1\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
            CloseServiceHandle(scm);
            return false;
        }

        printf("[+] \u5df2\u521b\u5efa\u9a71\u52a8\u670d\u52a1 '%s'\u3002\n", kDriverServiceName);
    }
    else
    {
        if (!ChangeServiceConfigA(
                service,
                SERVICE_NO_CHANGE,
                SERVICE_DEMAND_START,
                SERVICE_NO_CHANGE,
                driver_path.c_str(),
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                kDriverDisplayName))
        {
            PrintLastError("[!] \u66f4\u65b0\u9a71\u52a8\u670d\u52a1\u914d\u7f6e\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
        }
        else
        {
            printf("[+] \u5df2\u66f4\u65b0\u9a71\u52a8\u670d\u52a1\u8def\u5f84\u3002\n");
        }
    }

    SERVICE_STATUS_PROCESS status = { 0 };
    DWORD bytes_needed = 0;
    BOOL queried = QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytes_needed);

    if (queried)
    {
        printf("[*] \u542f\u52a8\u524d\u670d\u52a1\u72b6\u6001: %s\n", ServiceStateToText(status.dwCurrentState));
    }

    if (!StartServiceA(service, 0, NULL))
    {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("[+] \u9a71\u52a8\u670d\u52a1\u5df2\u7ecf\u5728\u8fd0\u884c\u3002\n");
        }
        else
        {
            PrintLastError("[-] \u542f\u52a8\u9a71\u52a8\u670d\u52a1\u5931\u8d25\uff0c\u9519\u8bef\u7801=", error);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
    }
    else
    {
        printf("[+] \u5df2\u53d1\u9001\u9a71\u52a8\u542f\u52a8\u8bf7\u6c42\u3002\n");
    }

    if (!WaitForDriverDevice(5000))
    {
        queried = QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytes_needed);

        if (queried)
        {
            printf("[-] \u7b49\u5f85\u540e\u670d\u52a1\u72b6\u6001: %s\n", ServiceStateToText(status.dwCurrentState));
            printf("[-] \u670d\u52a1\u9000\u51fa\u7801: 0x%lX\n", status.dwWin32ExitCode);
        }

        printf("[-] \u9a71\u52a8\u8bbe\u5907\u672a\u5c31\u7eea: %s\n", kDevicePath);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    printf("[+] \u9a71\u52a8\u52a0\u8f7d\u6210\u529f\uff0c\u8bbe\u5907\u5df2\u5c31\u7eea\u3002\n");

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
}

static bool StopDriverServiceSafely()
{
    HANDLE device = TryOpenDriverHandle();
    if (device != INVALID_HANDLE_VALUE)
    {
        printf("[*] 先尝试卸载全部 EPT Hook...\n");
        if (!SendSimpleIoctlHandle(device, IOCTL_HV_EPT_UNHOOK_ALL))
        {
            PrintLastError("[!] 卸载全部 EPT Hook 失败，错误码=", GetLastError());
            printf("[!] 将继续尝试安全停止 Hypervisor 驱动。\n");
        }
        else
        {
            printf("[+] 已请求卸载全部 EPT Hook。\n");
        }

        CloseHandle(device);
    }
    else
    {
        printf("[*] 当前驱动设备未打开，跳过 EPT Hook 清理步骤。\n");
    }

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
    {
        PrintLastError("[-] 打开服务管理器失败，错误码=", GetLastError());
        return false;
    }

    SC_HANDLE service = OpenServiceA(
        scm,
        kDriverServiceName,
        SERVICE_STOP | SERVICE_QUERY_STATUS);

    if (!service)
    {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            printf("[*] 驱动服务 '%s' 不存在，视为已卸载。\n", kDriverServiceName);
            CloseServiceHandle(scm);
            return true;
        }

        PrintLastError("[-] 打开驱动服务失败，错误码=", error);
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS status = {};
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytes_needed))
    {
        PrintLastError("[-] 查询驱动服务状态失败，错误码=", GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    if (status.dwCurrentState == SERVICE_STOPPED)
    {
        printf("[*] 驱动服务已经停止。\n");
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        if (!WaitForDriverDeviceGone(3000))
        {
            printf("[!] 服务虽已停止，但设备节点仍存在: %s\n", kDevicePath);
            return false;
        }

        printf("[+] Hypervisor 已安全卸载。\n");
        return true;
    }

    if (status.dwCurrentState != SERVICE_STOP_PENDING)
    {
        SERVICE_STATUS service_status = {};
        if (!ControlService(service, SERVICE_CONTROL_STOP, &service_status))
        {
            PrintLastError("[-] 发送停止驱动服务请求失败，错误码=", GetLastError());
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }

        printf("[*] 已发送 Hypervisor 停止请求。\n");
    }
    else
    {
        printf("[*] 驱动服务正在停止，等待完成...\n");
    }

    DWORD waited = 0;
    while (waited <= 10000)
    {
        if (!QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&status),
                sizeof(status),
                &bytes_needed))
        {
            PrintLastError("[-] 轮询驱动服务状态失败，错误码=", GetLastError());
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }

        if (status.dwCurrentState == SERVICE_STOPPED)
            break;

        Sleep(200);
        waited += 200;
    }

    if (status.dwCurrentState != SERVICE_STOPPED)
    {
        printf("[-] 等待驱动服务停止超时，当前状态: %s\n", ServiceStateToText(status.dwCurrentState));
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (!WaitForDriverDeviceGone(5000))
    {
        printf("[-] 驱动服务已停止，但设备节点仍未消失: %s\n", kDevicePath);
        return false;
    }

    printf("[+] Hypervisor 已安全卸载。\n");
    return true;
}

static bool ParseUnsignedValue(const char* text, unsigned long long* value)
{
    if (!text || !value)
        return false;

    char* end = NULL;
    unsigned long long parsed = strtoull(text, &end, 0);
    if (!end || *end != '\0')
        return false;

    *value = parsed;
    return true;
}

static bool ParsePatchHex(const char* text, std::vector<UCHAR>* bytes)
{
    if (!text || !bytes)
        return false;

    std::string compact;
    compact.reserve(strlen(text));

    for (const char* p = text; *p != '\0'; ++p)
    {
        if (*p == ' ' || *p == '\t' || *p == ',' || *p == '-')
            continue;

        compact.push_back(*p);
    }

    if (compact.empty() || (compact.size() % 2) != 0 || compact.size() > 32)
        return false;

    bytes->clear();
    bytes->reserve(compact.size() / 2);

    for (size_t i = 0; i < compact.size(); i += 2)
    {
        char byte_text[3] = { compact[i], compact[i + 1], '\0' };
        char* end = NULL;
        unsigned long value = strtoul(byte_text, &end, 16);
        if (!end || *end != '\0' || value > 0xFF)
            return false;

        bytes->push_back(static_cast<UCHAR>(value));
    }

    return true;
}

static void PrintPatch(const UCHAR* patch, size_t patch_size)
{
    for (size_t i = 0; i < patch_size; ++i)
    {
        printf("%02X", patch[i]);
        if (i + 1 != patch_size)
            printf(" ");
    }
}

static bool QueryProcessBitness(DWORD pid, bool* is_wow64)
{
    if (!is_wow64)
        return false;

    *is_wow64 = false;

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return false;

    BOOL wow64 = FALSE;
    BOOL ok = IsWow64Process(process, &wow64);
    CloseHandle(process);

    if (!ok)
        return false;

    *is_wow64 = (wow64 == TRUE);
    return true;
}

static std::string WideToAnsi(const wchar_t* text)
{
    if (!text)
        return std::string();

    int required = WideCharToMultiByte(CP_ACP, 0, text, -1, NULL, 0, NULL, NULL);
    if (required <= 1)
        return std::string();

    std::string output;
    output.resize(static_cast<size_t>(required));
    WideCharToMultiByte(CP_ACP, 0, text, -1, &output[0], required, NULL, NULL);
    output.resize(strlen(output.c_str()));
    return output;
}

static std::wstring AnsiToWide(const std::string& text)
{
    if (text.empty())
        return std::wstring();

    int required = MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, NULL, 0);
    if (required <= 1)
        return std::wstring();

    std::wstring output;
    output.resize(static_cast<size_t>(required));
    MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, &output[0], required);
    output.resize(wcslen(output.c_str()));
    return output;
}

static bool IsProcessAlive(DWORD pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return false;

    DWORD exit_code = 0;
    BOOL ok = GetExitCodeProcess(process, &exit_code);
    CloseHandle(process);

    return ok == TRUE && exit_code == STILL_ACTIVE;
}

static bool TryResolvePreferredTargetProcess(TargetContext* target)
{
    if (!target)
        return false;

    target->ProcessId = 0;
    target->GameDllBase = 0;
    target->ImageName.clear();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    DWORD resolved_pid = 0;
    UINT64 resolved_game_base = 0;
    std::string resolved_name;
    size_t best_priority = _countof(kPreferredTargetNames);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            for (size_t i = 0; i < _countof(kPreferredTargetNames); ++i)
            {
                if (_wcsicmp(entry.szExeFile, kPreferredTargetNames[i]) == 0)
                {
                    UINT64 module_base = 0;
                    if (TryGetModuleBase(entry.th32ProcessID, kDefaultModuleName, &module_base, NULL) &&
                        i < best_priority)
                    {
                        best_priority = i;
                        resolved_pid = entry.th32ProcessID;
                        resolved_game_base = module_base;
                        resolved_name = WideToAnsi(entry.szExeFile);
                    }
                    break;
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (resolved_pid == 0)
        return false;

    target->ProcessId = resolved_pid;
    target->GameDllBase = resolved_game_base;
    target->ImageName = resolved_name;

    return true;
}

static bool TryGetModuleBase(DWORD pid, const wchar_t* module_name, UINT64* base_address, std::string* resolved_name)
{
    if (!module_name || !base_address)
        return false;

    *base_address = 0;
    if (resolved_name)
        resolved_name->clear();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    bool found = false;
    if (Module32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szModule, module_name) == 0)
            {
                *base_address = static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(entry.modBaseAddr));
                if (resolved_name)
                    *resolved_name = WideToAnsi(entry.szModule);
                found = true;
                break;
            }
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return found;
}

static bool ResolveAddressToken(UINT64 game_dll_base, const std::string& token, UINT64* resolved_address, std::string* resolved_text)
{
    if (!resolved_address)
        return false;

    *resolved_address = 0;
    if (resolved_text)
        resolved_text->clear();

    size_t plus_pos = token.find('+');
    if (plus_pos != std::string::npos && plus_pos + 1 < token.size())
    {
        std::string offset_part = token.substr(plus_pos + 1);
        unsigned long long offset = 0;

        if (!ParseUnsignedValue(offset_part.c_str(), &offset))
            return false;

        *resolved_address = game_dll_base + offset;
        if (resolved_text)
        {
            char buffer[256] = { 0 };
            _snprintf_s(
                buffer,
                sizeof(buffer),
                _TRUNCATE,
                "game.dll+0x%llX -> 0x%p",
                offset,
                reinterpret_cast<void*>(static_cast<ULONG_PTR>(*resolved_address)));
            *resolved_text = buffer;
        }
        return true;
    }

    unsigned long long numeric_value = 0;
    if (!ParseUnsignedValue(token.c_str(), &numeric_value))
        return false;

    if (numeric_value < 0x10000000ULL)
    {
        *resolved_address = game_dll_base + numeric_value;
        if (resolved_text)
        {
            char buffer[256] = { 0 };
            _snprintf_s(
                buffer,
                sizeof(buffer),
                _TRUNCATE,
                "game.dll+0x%llX -> 0x%p",
                numeric_value,
                reinterpret_cast<void*>(static_cast<ULONG_PTR>(*resolved_address)));
            *resolved_text = buffer;
        }
        return true;
    }

    if (numeric_value >= kLegacyGameDllBase && numeric_value < 0x80000000ULL)
    {
        unsigned long long offset = numeric_value - kLegacyGameDllBase;
        *resolved_address = game_dll_base + offset;
        if (resolved_text)
        {
            char buffer[256] = { 0 };
            _snprintf_s(
                buffer,
                sizeof(buffer),
                _TRUNCATE,
                "game.dll+0x%llX -> 0x%p",
                offset,
                reinterpret_cast<void*>(static_cast<ULONG_PTR>(*resolved_address)));
            *resolved_text = buffer;
        }
        return true;
    }

    return false;
}

static bool RefreshTargetContext(TargetContext* target, bool verbose)
{
    if (!target)
        return false;

    if (target->ProcessId != 0 && IsProcessAlive(target->ProcessId))
    {
        UINT64 module_base = 0;
        if (TryGetModuleBase(target->ProcessId, kDefaultModuleName, &module_base, NULL))
        {
            target->GameDllBase = module_base;
            return true;
        }
    }

    TargetContext detected = { 0 };
    if (!TryResolvePreferredTargetProcess(&detected))
    {
        if (verbose)
        {
            printf("[-] \u6ca1\u6709\u627e\u5230\u53ef\u7528\u76ee\u6807\u3002\u9700\u8981 war3.exe \u6216 16_war3.exe\uff0c\u5e76\u4e14\u5176\u4e2d\u5df2\u52a0\u8f7d game.dll\u3002\n");
        }

        target->ProcessId = 0;
        target->GameDllBase = 0;
        target->ImageName.clear();
        return false;
    }

    *target = detected;

    if (verbose)
    {
        printf("[+] \u5df2\u81ea\u52a8\u8bc6\u522b\u76ee\u6807\u8fdb\u7a0b: %s (PID=%lu)\n", target->ImageName.c_str(), target->ProcessId);
        printf("[+] game.dll \u57fa\u5740: 0x%p\n", reinterpret_cast<void*>(static_cast<ULONG_PTR>(target->GameDllBase)));
    }

    return true;
}

static UINT32 ReadLe32(const UCHAR* bytes)
{
    return static_cast<UINT32>(bytes[0]) |
        (static_cast<UINT32>(bytes[1]) << 8) |
        (static_cast<UINT32>(bytes[2]) << 16) |
        (static_cast<UINT32>(bytes[3]) << 24);
}

static const char* GetX86RegNameByEncoding(UCHAR reg)
{
    switch (reg & 0x7)
    {
    case 0: return "eax";
    case 1: return "ecx";
    case 2: return "edx";
    case 3: return "ebx";
    case 4: return "esp";
    case 5: return "ebp";
    case 6: return "esi";
    case 7: return "edi";
    default: return "?";
    }
}

static const char* DescribeFfMemoryGroup(UCHAR reg)
{
    switch (reg & 0x7)
    {
    case 2: return "indirect call";
    case 4: return "indirect jmp";
    case 6: return "push [mem]";
    default: return "ff memory op";
    }
}

static const char* DescribeTableReadMnemonic32(UCHAR opcode1, UCHAR opcode2)
{
    if (opcode1 == 0x0F)
    {
        switch (opcode2)
        {
        case 0xB6: return "movzx byte-table read";
        case 0xB7: return "movzx word-table read";
        case 0xBE: return "movsx byte-table read";
        case 0xBF: return "movsx word-table read";
        default:   return "0F-prefixed table read";
        }
    }

    if (opcode1 == 0x8B)
        return "mov dword-table read";

    return "table read";
}

static bool IsAddressInPage(UINT64 page_base, UINT64 address)
{
    return address >= page_base && address < (page_base + kPageBytes);
}

static bool TryReadProcessPage(DWORD pid, UINT64 page_base, std::vector<UCHAR>* page_bytes)
{
    HANDLE process = NULL;
    SIZE_T bytes_read = 0;

    if (!page_bytes)
        return false;

    page_bytes->clear();
    process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return false;

    page_bytes->resize(kPageBytes);
    BOOL ok = ReadProcessMemory(
        process,
        reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(page_base)),
        page_bytes->data(),
        kPageBytes,
        &bytes_read);
    CloseHandle(process);

    if (ok != TRUE || bytes_read != kPageBytes)
    {
        page_bytes->clear();
        return false;
    }

    return true;
}

static void AddPageRiskFinding(
    PagePreflightReport* report,
    UINT64 address,
    UINT64 related_address,
    const std::string& category,
    const std::string& detail)
{
    if (!report)
        return;

    for (size_t i = 0; i < report->Findings.size(); ++i)
    {
        const PageRiskFinding& existing = report->Findings[i];
        if (existing.Address == address &&
            existing.RelatedAddress == related_address &&
            existing.Category == category)
        {
            return;
        }
    }

    if (report->Findings.size() >= 12)
        return;

    PageRiskFinding finding = {};
    finding.Address = address;
    finding.RelatedAddress = related_address;
    finding.Category = category;
    finding.Detail = detail;
    report->Findings.push_back(finding);
}

static void ScanIndirectDispatch32(
    UINT64 game_dll_base,
    const std::vector<UCHAR>& page_bytes,
    PagePreflightReport* report)
{
    if (!report)
        return;

    for (size_t offset = 0; offset + 6 <= page_bytes.size(); ++offset)
    {
        UCHAR opcode = page_bytes[offset];
        UCHAR modrm;
        UCHAR reg;
        UCHAR mod;
        UCHAR rm;
        UCHAR sib = 0;
        UCHAR sib_scale = 0;
        UCHAR sib_index = 0;
        UCHAR sib_base = 0;
        UINT64 instruction_address;
        UINT64 table_address = 0;
        bool has_definite_same_page_reference = false;
        bool has_sib = false;
        std::ostringstream detail;

        if (opcode != 0xFF)
            continue;

        modrm = page_bytes[offset + 1];
        reg = static_cast<UCHAR>((modrm >> 3) & 0x7);
        mod = static_cast<UCHAR>((modrm >> 6) & 0x3);
        rm = static_cast<UCHAR>(modrm & 0x7);

        if (reg != 2 && reg != 4 && reg != 6)
            continue;

        if (mod == 3)
            continue;

        if (mod == 0 && rm == 5)
        {
            table_address = ReadLe32(&page_bytes[offset + 2]);
            has_definite_same_page_reference = IsAddressInPage(report->PageBase, table_address);
        }
        else if (mod == 0 && rm == 4 && offset + 7 <= page_bytes.size())
        {
            sib = page_bytes[offset + 2];
            sib_scale = static_cast<UCHAR>((sib >> 6) & 0x3);
            sib_index = static_cast<UCHAR>((sib >> 3) & 0x7);
            sib_base = static_cast<UCHAR>(sib & 0x7);
            has_sib = true;

            if (sib_base == 5)
            {
                table_address = ReadLe32(&page_bytes[offset + 3]);
                has_definite_same_page_reference = IsAddressInPage(report->PageBase, table_address);
            }
        }

        instruction_address = report->PageBase + offset;

        if (has_definite_same_page_reference)
        {
            detail << "32-bit " << DescribeFfMemoryGroup(reg)
                   << " reads a same-page table at "
                   << FormatGameDllAddress(game_dll_base, table_address);

            if (has_sib)
            {
                detail << " using ";
                if (sib_index != 4)
                {
                    detail << GetX86RegNameByEncoding(sib_index)
                           << "*" << (1U << sib_scale);
                }
                else
                {
                    detail << "no index";
                }
            }

            detail << ". This page is code+data mixed and is prone to EPT read ping-pong under X-only fake pages.";
            AddPageRiskFinding(
                report,
                instruction_address,
                table_address,
                std::string("same-page ") + DescribeFfMemoryGroup(reg),
                detail.str());
            continue;
        }

        if (has_sib)
        {
            detail << "32-bit " << DescribeFfMemoryGroup(reg)
                   << " uses SIB addressing";

            if (sib_index != 4)
            {
                detail << " (" << GetX86RegNameByEncoding(sib_index)
                       << "*" << (1U << sib_scale) << ")";
            }

            if (sib_base != 5 || mod != 0)
            {
                detail << " with a runtime base register";
            }
            else
            {
                detail << " with disp32 base "
                       << FormatGameDllAddress(game_dll_base, table_address);
            }

            detail << ". Even if the target is runtime-dependent, this FF-family dispatch can become a hot read source on mixed pages.";
            AddPageRiskFinding(
                report,
                instruction_address,
                table_address,
                std::string("ff-family indexed ") + DescribeFfMemoryGroup(reg),
                detail.str());
        }
    }
}

static void ScanIndexedLookupReads32(
    UINT64 game_dll_base,
    const std::vector<UCHAR>& page_bytes,
    PagePreflightReport* report)
{
    if (!report)
        return;

    for (size_t offset = 0; offset + 3 <= page_bytes.size(); ++offset)
    {
        size_t pos = offset;
        UCHAR opcode1 = 0;
        UCHAR opcode2 = 0;
        UCHAR modrm = 0;
        UCHAR mod = 0;
        UCHAR rm = 0;
        UCHAR sib = 0;
        UCHAR sib_scale = 0;
        UCHAR sib_index = 0;
        UCHAR sib_base = 0;
        bool has_sib = false;
        bool has_disp32 = false;
        size_t modrm_pos = 0;
        size_t disp32_pos = 0;
        UINT64 table_address = 0;
        UINT64 instruction_address = 0;
        std::ostringstream detail;

        while (pos < page_bytes.size())
        {
            UCHAR prefix = page_bytes[pos];
            if (prefix == 0x66 || prefix == 0x67)
            {
                pos = page_bytes.size();
                break;
            }

            if (prefix == 0xF0 || prefix == 0xF2 || prefix == 0xF3 ||
                prefix == 0x2E || prefix == 0x36 || prefix == 0x3E ||
                prefix == 0x26 || prefix == 0x64 || prefix == 0x65)
            {
                ++pos;
                continue;
            }

            break;
        }

        if (pos >= page_bytes.size())
            continue;

        opcode1 = page_bytes[pos];
        if (opcode1 == 0x0F)
        {
            if (pos + 3 > page_bytes.size())
                continue;

            opcode2 = page_bytes[pos + 1];
            if (opcode2 != 0xB6 && opcode2 != 0xB7 &&
                opcode2 != 0xBE && opcode2 != 0xBF)
            {
                continue;
            }

            modrm_pos = pos + 2;
        }
        else if (opcode1 == 0x8B)
        {
            opcode2 = 0;
            if (pos + 2 > page_bytes.size())
                continue;
            modrm_pos = pos + 1;
        }
        else
        {
            continue;
        }

        modrm = page_bytes[modrm_pos];
        mod = static_cast<UCHAR>((modrm >> 6) & 0x3);
        rm = static_cast<UCHAR>(modrm & 0x7);
        if (mod == 3)
            continue;

        disp32_pos = modrm_pos + 1;
        if (rm == 4)
        {
            if (disp32_pos >= page_bytes.size())
                continue;

            sib = page_bytes[disp32_pos++];
            sib_scale = static_cast<UCHAR>((sib >> 6) & 0x3);
            sib_index = static_cast<UCHAR>((sib >> 3) & 0x7);
            sib_base = static_cast<UCHAR>(sib & 0x7);
            has_sib = true;

            if ((sib_base == 5 && mod == 0) || mod == 2)
                has_disp32 = true;
        }
        else if ((mod == 0 && rm == 5) || mod == 2)
        {
            has_disp32 = true;
        }

        if (!has_disp32 || disp32_pos + 4 > page_bytes.size())
            continue;

        table_address = ReadLe32(&page_bytes[disp32_pos]);
        if (!IsAddressInPage(report->PageBase, table_address))
            continue;

        instruction_address = report->PageBase + offset;
        detail << "32-bit " << DescribeTableReadMnemonic32(opcode1, opcode2)
               << " reads a same-page lookup table at "
               << FormatGameDllAddress(game_dll_base, table_address);

        if (has_sib)
        {
            if (sib_index != 4)
            {
                detail << " using " << GetX86RegNameByEncoding(sib_index)
                       << "*" << (1U << sib_scale);
            }

            if (sib_base != 5 || mod != 0)
                detail << " with a runtime base register";
        }
        else if (rm != 5)
        {
            detail << " using " << GetX86RegNameByEncoding(rm)
                   << " with a runtime base register";
        }

        detail << ". This kind of same-page lookup table often causes EPT read ping-pong under X-only fake pages.";
        AddPageRiskFinding(
            report,
            instruction_address,
            table_address,
            "same-page indexed lookup read",
            detail.str());
    }
}

static void ScanSamePagePointerRuns32(
    UINT64 game_dll_base,
    const std::vector<UCHAR>& page_bytes,
    PagePreflightReport* report)
{
    size_t run_start = 0;
    size_t run_count = 0;

    if (!report)
        return;

    for (size_t offset = 0; offset + 4 <= page_bytes.size(); offset += 4)
    {
        UINT64 value = static_cast<UINT64>(ReadLe32(&page_bytes[offset]));
        bool same_page = IsAddressInPage(report->PageBase, value);

        if (same_page)
        {
            if (run_count == 0)
                run_start = offset;
            ++run_count;
        }
        else if (run_count != 0)
        {
            if (run_count >= 3)
            {
                UINT64 table_address = report->PageBase + run_start;
                UINT64 first_target = static_cast<UINT64>(ReadLe32(&page_bytes[run_start]));
                std::ostringstream detail;
                detail << "Found " << run_count
                       << " consecutive DWORDs that point back into the same page, starting at "
                       << FormatGameDllAddress(game_dll_base, table_address)
                       << ". This looks like an embedded jump table; first target is "
                       << FormatGameDllAddress(game_dll_base, first_target) << ".";
                AddPageRiskFinding(
                    report,
                    table_address,
                    first_target,
                    "embedded same-page pointer table",
                    detail.str());
            }

            run_count = 0;
        }
    }

    if (run_count >= 3)
    {
        UINT64 table_address = report->PageBase + run_start;
        UINT64 first_target = static_cast<UINT64>(ReadLe32(&page_bytes[run_start]));
        std::ostringstream detail;
        detail << "Found " << run_count
               << " consecutive DWORDs that point back into the same page, starting at "
               << FormatGameDllAddress(game_dll_base, table_address)
               << ". This looks like an embedded jump table; first target is "
               << FormatGameDllAddress(game_dll_base, first_target) << ".";
        AddPageRiskFinding(
            report,
            table_address,
            first_target,
            "embedded same-page pointer table",
            detail.str());
    }
}

static void SortPageFindings(PagePreflightReport* report)
{
    if (!report)
        return;

    std::sort(
        report->Findings.begin(),
        report->Findings.end(),
        [](const PageRiskFinding& lhs, const PageRiskFinding& rhs)
        {
            if (lhs.Address != rhs.Address)
                return lhs.Address < rhs.Address;
            if (lhs.RelatedAddress != rhs.RelatedAddress)
                return lhs.RelatedAddress < rhs.RelatedAddress;
            return lhs.Category < rhs.Category;
        });
}

static bool RunPagePreflight(
    const TargetContext& target,
    UINT64 address,
    bool is_wow64,
    PagePreflightReport* report)
{
    std::vector<UCHAR> page_bytes;

    if (!report)
        return false;

    report->RequestedAddress = address;
    report->PageBase = address & ~static_cast<UINT64>(kPageBytes - 1);
    report->IsWow64 = is_wow64;
    report->ReadSucceeded = false;
    report->Findings.clear();

    if (!TryReadProcessPage(target.ProcessId, report->PageBase, &page_bytes))
        return false;

    report->ReadSucceeded = true;

    if (is_wow64)
    {
        ScanIndirectDispatch32(target.GameDllBase, page_bytes, report);
        ScanIndexedLookupReads32(target.GameDllBase, page_bytes, report);
        ScanSamePagePointerRuns32(target.GameDllBase, page_bytes, report);
    }

    SortPageFindings(report);
    return true;
}

static void AddFastRule(
    std::vector<EPT_HOOK_FAST_RULE>* rules,
    const EPT_HOOK_FAST_RULE& rule)
{
    if (!rules || rule.Type == EptHookFastRuleNone || rule.OpcodeLength == 0)
        return;

    for (size_t i = 0; i < rules->size(); ++i)
    {
        const EPT_HOOK_FAST_RULE& existing = (*rules)[i];
        if (existing.RipOffset == rule.RipOffset &&
            existing.Type == rule.Type &&
            existing.GlaOffsetStart == rule.GlaOffsetStart)
        {
            return;
        }
    }

    if (rules->size() >= EPT_HOOK_MAX_FAST_RULES)
        return;

    rules->push_back(rule);
}

static size_t ParseModrmMemoryLength32(
    const std::vector<UCHAR>& bytes,
    size_t modrm_pos)
{
    if (modrm_pos >= bytes.size())
        return 0;

    UCHAR modrm = bytes[modrm_pos];
    UCHAR mod = static_cast<UCHAR>((modrm >> 6) & 0x3);
    UCHAR rm = static_cast<UCHAR>(modrm & 0x7);
    size_t pos = modrm_pos + 1;

    if (mod == 3)
        return 0;

    if (rm == 4)
    {
        if (pos >= bytes.size())
            return 0;

        UCHAR sib = bytes[pos++];
        if ((sib & 0x7) == 5 && mod == 0)
        {
            if (pos + 4 > bytes.size())
                return 0;
            pos += 4;
        }
    }
    else if (mod == 0 && rm == 5)
    {
        if (pos + 4 > bytes.size())
            return 0;
        pos += 4;
    }

    if (mod == 1)
    {
        if (pos + 1 > bytes.size())
            return 0;
        pos += 1;
    }
    else if (mod == 2)
    {
        if (pos + 4 > bytes.size())
            return 0;
        pos += 4;
    }

    return pos - modrm_pos;
}

static void BuildFastRules32(
    UINT64 page_base,
    const std::vector<UCHAR>& page_bytes,
    std::vector<EPT_HOOK_FAST_RULE>* rules)
{
    if (!rules)
        return;

    rules->clear();

    for (size_t offset = 0; offset + 3 <= page_bytes.size(); ++offset)
    {
        size_t pos = offset;

        while (pos < page_bytes.size())
        {
            UCHAR prefix = page_bytes[pos];
            if (prefix == 0x66 || prefix == 0x67)
            {
                pos = page_bytes.size();
                break;
            }

            if (prefix == 0xF0 || prefix == 0xF2 || prefix == 0xF3 ||
                prefix == 0x2E || prefix == 0x36 || prefix == 0x3E ||
                prefix == 0x26 || prefix == 0x64 || prefix == 0x65)
            {
                ++pos;
                continue;
            }

            break;
        }

        if (pos >= page_bytes.size())
            continue;

        if (page_bytes[pos] == 0x0F)
        {
            EPT_HOOK_FAST_RULE rule = {};
            UCHAR opcode2;
            UCHAR modrm;
            UCHAR mod;
            UCHAR rm;
            size_t modrm_pos;
            size_t disp32_pos;
            UINT32 table_address;

            if (pos + 3 > page_bytes.size())
                continue;

            opcode2 = page_bytes[pos + 1];
            if (opcode2 != 0xB6 && opcode2 != 0xB7 &&
                opcode2 != 0xBE && opcode2 != 0xBF)
            {
                continue;
            }

            modrm_pos = pos + 2;
            modrm = page_bytes[modrm_pos];
            mod = static_cast<UCHAR>((modrm >> 6) & 0x3);
            rm = static_cast<UCHAR>(modrm & 0x7);
            if (mod == 3)
                continue;

            disp32_pos = modrm_pos + 1;
            if (rm == 4)
            {
                if (disp32_pos >= page_bytes.size())
                    continue;

                UCHAR sib = page_bytes[disp32_pos++];
                if (!(((sib & 0x7) == 5 && mod == 0) || mod == 2))
                    continue;
            }
            else if (!((mod == 0 && rm == 5) || mod == 2))
            {
                continue;
            }

            if (disp32_pos + 4 > page_bytes.size())
                continue;

            table_address = ReadLe32(&page_bytes[disp32_pos]);
            if (!IsAddressInPage(page_base, table_address))
                continue;

            rule.RipOffset = static_cast<UINT16>(offset);
            rule.GlaOffsetStart = static_cast<UINT16>(table_address - page_base);
            rule.GlaOffsetEnd = static_cast<UINT16>(kPageBytes - 1);
            rule.Type = (opcode2 == 0xBE || opcode2 == 0xBF) ? EptHookFastRuleLookupMovsx : EptHookFastRuleLookupMovzx;
            rule.DestReg = static_cast<UINT8>((modrm >> 3) & 0x7);
            rule.DataSize = (opcode2 == 0xB7 || opcode2 == 0xBF) ? 2 : 1;
            rule.InsnLength = 0;
            rule.Opcode[0] = 0x0F;
            rule.Opcode[1] = opcode2;
            rule.Opcode[2] = modrm;
            rule.OpcodeLength = 3;
            AddFastRule(rules, rule);
            continue;
        }

        if (page_bytes[pos] == 0x8B)
        {
            EPT_HOOK_FAST_RULE rule = {};
            UCHAR modrm;
            UCHAR mod;
            UCHAR rm;
            size_t modrm_pos = pos + 1;
            size_t disp32_pos = modrm_pos + 1;
            UINT32 table_address;

            if (pos + 2 > page_bytes.size())
                continue;

            modrm = page_bytes[modrm_pos];
            mod = static_cast<UCHAR>((modrm >> 6) & 0x3);
            rm = static_cast<UCHAR>(modrm & 0x7);
            if (mod == 3)
                continue;

            if (rm == 4)
            {
                if (disp32_pos >= page_bytes.size())
                    continue;

                UCHAR sib = page_bytes[disp32_pos++];
                if (!(((sib & 0x7) == 5 && mod == 0) || mod == 2))
                    continue;
            }
            else if (!((mod == 0 && rm == 5) || mod == 2))
            {
                continue;
            }

            if (disp32_pos + 4 > page_bytes.size())
                continue;

            table_address = ReadLe32(&page_bytes[disp32_pos]);
            if (!IsAddressInPage(page_base, table_address))
                continue;

            rule.RipOffset = static_cast<UINT16>(offset);
            rule.GlaOffsetStart = static_cast<UINT16>(table_address - page_base);
            rule.GlaOffsetEnd = static_cast<UINT16>(kPageBytes - 1);
            rule.Type = EptHookFastRuleLookupMov;
            rule.DestReg = static_cast<UINT8>((modrm >> 3) & 0x7);
            rule.DataSize = 4;
            rule.InsnLength = 0;
            rule.Opcode[0] = 0x8B;
            rule.Opcode[1] = modrm;
            rule.OpcodeLength = 2;
            AddFastRule(rules, rule);
            continue;
        }

        if (page_bytes[pos] == 0xFF)
        {
            EPT_HOOK_FAST_RULE rule = {};
            UCHAR modrm;
            UCHAR reg;
            UCHAR mod;
            UCHAR rm;
            size_t modrm_pos = pos + 1;
            size_t disp32_pos = modrm_pos + 1;
            UINT32 table_address;
            size_t modrm_len;

            if (pos + 2 > page_bytes.size())
                continue;

            modrm = page_bytes[modrm_pos];
            reg = static_cast<UCHAR>((modrm >> 3) & 0x7);
            mod = static_cast<UCHAR>((modrm >> 6) & 0x3);
            rm = static_cast<UCHAR>(modrm & 0x7);
            if ((reg != 2 && reg != 4) || mod == 3)
                continue;

            if (rm == 4)
            {
                if (disp32_pos >= page_bytes.size())
                    continue;

                UCHAR sib = page_bytes[disp32_pos++];
                if (!(((sib & 0x7) == 5 && mod == 0) || mod == 2))
                    continue;
            }
            else if (!((mod == 0 && rm == 5) || mod == 2))
            {
                continue;
            }

            if (disp32_pos + 4 > page_bytes.size())
                continue;

            table_address = ReadLe32(&page_bytes[disp32_pos]);
            if (!IsAddressInPage(page_base, table_address))
                continue;

            modrm_len = ParseModrmMemoryLength32(page_bytes, modrm_pos);
            if (modrm_len == 0)
                continue;

            rule.RipOffset = static_cast<UINT16>(offset);
            rule.GlaOffsetStart = static_cast<UINT16>(table_address - page_base);
            rule.GlaOffsetEnd = static_cast<UINT16>(kPageBytes - 1);
            rule.Type = (reg == 2) ? EptHookFastRuleFfCall : EptHookFastRuleFfJmp;
            rule.DestReg = 0xFF;
            rule.DataSize = 4;
            rule.InsnLength = static_cast<UINT8>(1 + modrm_len);
            rule.Opcode[0] = 0xFF;
            rule.Opcode[1] = modrm;
            rule.OpcodeLength = 2;
            if (rm == 4 && pos + 3 <= page_bytes.size())
            {
                rule.Opcode[2] = page_bytes[pos + 2];
                rule.OpcodeLength = 3;
            }
            AddFastRule(rules, rule);
        }
    }
}

static void InstallPreScannedFastRulesForHook(
    HANDLE device,
    const TargetContext& target,
    const HookSpec& spec,
    bool is_wow64)
{
    std::vector<UCHAR> page_bytes;
    std::vector<EPT_HOOK_FAST_RULE> rules;
    EPT_HOOK_FAST_RULES_REQUEST req = {};

    if (!device || device == INVALID_HANDLE_VALUE || !is_wow64)
        return;

    if (!TryReadProcessPage(target.ProcessId, spec.Address & ~static_cast<UINT64>(kPageBytes - 1), &page_bytes))
        return;

    BuildFastRules32(spec.Address & ~static_cast<UINT64>(kPageBytes - 1), page_bytes, &rules);
    if (rules.empty())
        return;

    req.ProcessId = target.ProcessId;
    req.VirtualAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(spec.Address));
    req.RuleCount = static_cast<UINT32>(rules.size());
    for (size_t i = 0; i < rules.size() && i < EPT_HOOK_MAX_FAST_RULES; ++i)
        req.Rules[i] = rules[i];

    if (SendFastRulesHandle(device, &req))
    {
        printf("[*] 已下发 %u 条预扫描 fast-rule，用于同页 lookup/jmp 热点快速仿真。\n", req.RuleCount);
    }
    else
    {
        PrintLastError("[!] 下发预扫描 fast-rule 失败，错误码=", GetLastError());
    }
}

static void PrintPagePreflightReport(
    const TargetContext& target,
    const HookSpec& spec,
    const PagePreflightReport& report)
{
    printf("[*] 安装前预检: %s\n", spec.ResolvedAddressText.c_str());
    printf("    Page=%s  Mode=%s\n",
        FormatGameDllAddress(target.GameDllBase, report.PageBase).c_str(),
        report.IsWow64 ? "WOW64 / 32位规则" : "基础规则");

    if (!report.ReadSucceeded)
    {
        printf("    [!] 无法读取目标页，跳过预检。\n");
        return;
    }

    if (report.Findings.empty())
    {
        printf("    [+] 未发现明显的同页跳表/绝对间接分发特征，但这不代表绝对安全。\n");
        return;
    }

    printf("    [!] 发现 %zu 个高风险特征，说明这页可能是代码+数据混排页。\n", report.Findings.size());
    for (size_t i = 0; i < report.Findings.size(); ++i)
    {
        const PageRiskFinding& finding = report.Findings[i];

        printf("      %zu. %s\n", i + 1, finding.Category.c_str());
        printf("         at=%s",
            FormatGameDllAddress(target.GameDllBase, finding.Address).c_str());
        if (finding.RelatedAddress != 0)
        {
            printf("  ref=%s",
                FormatGameDllAddress(target.GameDllBase, finding.RelatedAddress).c_str());
        }
        printf("\n");
        printf("         %s\n", finding.Detail.c_str());
    }
}

static bool SendHookRequestHandle(HANDLE device, const EPT_HOOK_REQUEST* req)
{
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_HV_EPT_HOOK,
        (LPVOID)req,
        sizeof(*req),
        NULL,
        0,
        &bytes_returned,
        NULL);

    return ok == TRUE;
}

static bool SendUnhookRequestHandle(HANDLE device, const EPT_HOOK_UNHOOK_REQUEST* req)
{
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_HV_EPT_UNHOOK,
        (LPVOID)req,
        sizeof(*req),
        NULL,
        0,
        &bytes_returned,
        NULL);

    return ok == TRUE;
}

static bool SendUnhookPageRequestHandle(HANDLE device, const EPT_HOOK_UNHOOK_REQUEST* req)
{
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_HV_EPT_UNHOOK_PAGE,
        (LPVOID)req,
        sizeof(*req),
        NULL,
        0,
        &bytes_returned,
        NULL);

    return ok == TRUE;
}

static bool SendFastRulesHandle(HANDLE device, const EPT_HOOK_FAST_RULES_REQUEST* req)
{
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_HV_EPT_SET_FAST_RULES,
        (LPVOID)req,
        sizeof(*req),
        NULL,
        0,
        &bytes_returned,
        NULL);

    return ok == TRUE;
}

static bool SendSimpleIoctlHandle(HANDLE device, DWORD ioctl_code)
{
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        ioctl_code,
        NULL,
        0,
        NULL,
        0,
        &bytes_returned,
        NULL);

    return ok == TRUE;
}

static bool QueryHookStatsHandle(
    HANDLE device,
    const EPT_HOOK_STATS_QUERY* query,
    EPT_HOOK_STATS_RESULT* result)
{
    DWORD bytes_returned = 0;
    BOOL ok;

    if (!query || !result)
        return false;

    ZeroMemory(result, sizeof(*result));
    ok = DeviceIoControl(
        device,
        IOCTL_HV_EPT_QUERY_HOOK_STATS,
        (LPVOID)query,
        sizeof(*query),
        result,
        sizeof(*result),
        &bytes_returned,
        NULL);

    return ok == TRUE && bytes_returned >= offsetof(EPT_HOOK_STATS_RESULT, FfRawFailMode);
}

static std::string DescribeViolationFlags(UINT32 flags)
{
    std::ostringstream stream;

    if (flags & HV_HOOK_FAULT_FLAG_EXECUTE)
        stream << "EXEC ";
    if (flags & HV_HOOK_FAULT_FLAG_READ)
        stream << "READ ";
    if (flags & HV_HOOK_FAULT_FLAG_WRITE)
        stream << "WRITE ";
    if (flags & HV_HOOK_FAULT_FLAG_LINEAR_VALID)
        stream << "GLA ";
    if (flags & HV_HOOK_FAULT_FLAG_CONTEXT_MATCH)
        stream << "CTX ";

    std::string text = stream.str();
    if (text.empty())
        return "NONE";

    if (!text.empty() && text.back() == ' ')
        text.pop_back();
    return text;
}

static std::string FormatGameDllAddress(UINT64 game_dll_base, UINT64 address)
{
    char buffer[256] = { 0 };

    if (address == 0)
    {
        _snprintf_s(buffer, sizeof(buffer), _TRUNCATE, "0x0");
        return buffer;
    }

    if (game_dll_base != 0 && address >= game_dll_base && (address - game_dll_base) < 0x10000000ULL)
    {
        _snprintf_s(
            buffer,
            sizeof(buffer),
            _TRUNCATE,
            "game.dll+0x%llX (0x%p)",
            address - game_dll_base,
            reinterpret_cast<void*>(static_cast<ULONG_PTR>(address)));
        return buffer;
    }

    _snprintf_s(
        buffer,
        sizeof(buffer),
        _TRUNCATE,
        "0x%p",
        reinterpret_cast<void*>(static_cast<ULONG_PTR>(address)));
    return buffer;
}

static UINT64 GetLargePageRegionBase(UINT64 address)
{
    return address & ~(kLargePageBytes - 1ULL);
}

static void RememberInstalledHook(const TargetContext& target, const HookSpec& spec)
{
    for (size_t i = 0; i < g_session_installed_hooks.size(); ++i)
    {
        SessionInstalledHook& existing = g_session_installed_hooks[i];
        if (existing.ProcessId == target.ProcessId && existing.Address == spec.Address)
        {
            existing.SourceAddressText = spec.SourceAddressText;
            existing.ResolvedAddressText = spec.ResolvedAddressText;
            return;
        }
    }

    SessionInstalledHook entry = {};
    entry.ProcessId = target.ProcessId;
    entry.Address = spec.Address;
    entry.SourceAddressText = spec.SourceAddressText;
    entry.ResolvedAddressText = spec.ResolvedAddressText;
    g_session_installed_hooks.push_back(entry);
}

static void ForgetInstalledHook(DWORD process_id, UINT64 address)
{
    for (std::vector<SessionInstalledHook>::iterator it = g_session_installed_hooks.begin();
         it != g_session_installed_hooks.end();)
    {
        if (it->ProcessId == process_id && it->Address == address)
            it = g_session_installed_hooks.erase(it);
        else
            ++it;
    }
}

static void ForgetInstalledHookPage(DWORD process_id, UINT64 address)
{
    UINT64 page_base = address & ~(static_cast<UINT64>(kPageBytes) - 1ULL);

    for (std::vector<SessionInstalledHook>::iterator it = g_session_installed_hooks.begin();
         it != g_session_installed_hooks.end();)
    {
        UINT64 existing_page = it->Address & ~(static_cast<UINT64>(kPageBytes) - 1ULL);
        if (it->ProcessId == process_id && existing_page == page_base)
            it = g_session_installed_hooks.erase(it);
        else
            ++it;
    }
}

static void ForgetAllInstalledHooks(DWORD process_id)
{
    for (std::vector<SessionInstalledHook>::iterator it = g_session_installed_hooks.begin();
         it != g_session_installed_hooks.end();)
    {
        if (it->ProcessId == process_id)
            it = g_session_installed_hooks.erase(it);
        else
            ++it;
    }
}

static void PrintHookBatchRegionSummary(const TargetContext& target, const std::vector<HookSpec>& hooks)
{
    std::vector<UINT64> region_bases;
    std::vector<size_t> region_hook_counts;

    for (size_t i = 0; i < hooks.size(); ++i)
    {
        UINT64 region_base = GetLargePageRegionBase(hooks[i].Address);
        size_t region_index = 0;

        for (; region_index < region_bases.size(); ++region_index)
        {
            if (region_bases[region_index] == region_base)
                break;
        }

        if (region_index == region_bases.size())
        {
            region_bases.push_back(region_base);
            region_hook_counts.push_back(0);
        }

        ++region_hook_counts[region_index];
    }

    printf("[*] 2MB 区域概览: %zu 个 Hook 分布在 %zu 个 large-page 区域\n",
        hooks.size(),
        region_bases.size());

    for (size_t i = 0; i < region_bases.size(); ++i)
    {
        UINT64 region_base = region_bases[i];
        UINT64 region_end = region_base + kLargePageBytes - 1;

        printf("    %s ~ %s : %zu 个 Hook\n",
            FormatGameDllAddress(target.GameDllBase, region_base).c_str(),
            FormatGameDllAddress(target.GameDllBase, region_end).c_str(),
            region_hook_counts[i]);
    }

    if (!region_bases.empty())
        printf("    [!] 同一 2MB 区域里只要有 1 个 Hook，就已经会触发 2MB -> 4KB 拆页。\n");
}

static void PrintHookHotspots(const TargetContext& target, const EPT_HOOK_STATS_RESULT& result)
{
    if (result.HotspotCount == 0)
    {
        printf("    Hotspots: none\n");
        return;
    }

    printf("    Hotspots: top %u (sampled 1/%u)\n",
        result.HotspotCount,
        result.HotspotSampleEvery != 0 ? result.HotspotSampleEvery : 1);

    for (UINT32 i = 0; i < EPT_HOOK_HOTSPOT_COUNT; ++i)
    {
        const EPT_HOOK_HOTSPOT_RESULT& hotspot = result.Hotspots[i];
        unsigned long long rip_page_offset = 0;
        unsigned long long gla_page_offset = 0;

        if (hotspot.HitCount == 0)
            break;

        if (hotspot.Rip >= result.TargetPageBase)
            rip_page_offset = hotspot.Rip - result.TargetPageBase;

        if (hotspot.GuestLinear >= result.TargetPageBase)
            gla_page_offset = hotspot.GuestLinear - result.TargetPageBase;

        printf("      #%u hits=%llu flags=%s\n",
            i + 1,
            hotspot.HitCount,
            DescribeViolationFlags(hotspot.Flags).c_str());
        printf("         rip=%s  page+0x%llX\n",
            FormatGameDllAddress(target.GameDllBase, hotspot.Rip).c_str(),
            rip_page_offset);
        printf("         gla=%s  page+0x%llX  gpa=0x%llX\n",
            FormatGameDllAddress(target.GameDllBase, hotspot.GuestLinear).c_str(),
            gla_page_offset,
            hotspot.GuestPhysical);
    }
}

static UINT64 CounterDelta(UINT64 current, UINT64 baseline)
{
    return current >= baseline ? (current - baseline) : 0;
}

static bool TryFindExecReadHotspotPair(
    const EPT_HOOK_STATS_RESULT& result,
    const EPT_HOOK_HOTSPOT_RESULT** exec_hotspot,
    const EPT_HOOK_HOTSPOT_RESULT** read_hotspot)
{
    if (exec_hotspot)
        *exec_hotspot = NULL;
    if (read_hotspot)
        *read_hotspot = NULL;

    for (UINT32 i = 0; i < EPT_HOOK_HOTSPOT_COUNT; ++i)
    {
        const EPT_HOOK_HOTSPOT_RESULT& first = result.Hotspots[i];
        if (first.HitCount == 0)
            continue;

        for (UINT32 j = 0; j < EPT_HOOK_HOTSPOT_COUNT; ++j)
        {
            const EPT_HOOK_HOTSPOT_RESULT& second = result.Hotspots[j];
            if (second.HitCount == 0)
                continue;

            if (first.Rip != second.Rip)
                continue;

            const bool first_exec = (first.Flags & HV_HOOK_FAULT_FLAG_EXECUTE) != 0;
            const bool first_read = (first.Flags & HV_HOOK_FAULT_FLAG_READ) != 0;
            const bool second_exec = (second.Flags & HV_HOOK_FAULT_FLAG_EXECUTE) != 0;
            const bool second_read = (second.Flags & HV_HOOK_FAULT_FLAG_READ) != 0;

            if (first_exec && second_read)
            {
                if (exec_hotspot)
                    *exec_hotspot = &first;
                if (read_hotspot)
                    *read_hotspot = &second;
                return true;
            }

            if (first_read && second_exec)
            {
                if (exec_hotspot)
                    *exec_hotspot = &second;
                if (read_hotspot)
                    *read_hotspot = &first;
                return true;
            }
        }
    }

    return false;
}

static void PrintPingPongAssessment(
    const TargetContext& target,
    const EPT_HOOK_STATS_RESULT& current,
    const EPT_HOOK_STATS_RESULT* baseline)
{
    UINT64 delta_exec = 0;
    UINT64 delta_read = 0;
    UINT64 delta_mtf = 0;
    UINT64 delta_emu_success = 0;
    UINT64 delta_emu_failure = 0;
    UINT64 delta_ff_shortcut = 0;
    const EPT_HOOK_HOTSPOT_RESULT* exec_hotspot = NULL;
    const EPT_HOOK_HOTSPOT_RESULT* read_hotspot = NULL;
    const bool has_pair = TryFindExecReadHotspotPair(current, &exec_hotspot, &read_hotspot);
    bool same_page_read = false;
    bool healthy = false;
    bool strong_suspect = false;
    bool suspect = false;

    if (baseline)
    {
        delta_exec = CounterDelta(current.ExecuteViolations, baseline->ExecuteViolations);
        delta_read = CounterDelta(current.ReadViolations, baseline->ReadViolations);
        delta_mtf = CounterDelta(current.MtfCount, baseline->MtfCount);
        delta_emu_success = CounterDelta(current.EmulationSuccesses, baseline->EmulationSuccesses);
        delta_emu_failure = CounterDelta(current.EmulationFailures, baseline->EmulationFailures);
        delta_ff_shortcut = CounterDelta(current.FfShortcutSuccess, baseline->FfShortcutSuccess);
    }
    else
    {
        delta_exec = current.ExecuteViolations;
        delta_read = current.ReadViolations;
        delta_mtf = current.MtfCount;
        delta_emu_success = current.EmulationSuccesses;
        delta_emu_failure = current.EmulationFailures;
        delta_ff_shortcut = current.FfShortcutSuccess;
    }

    if (read_hotspot)
    {
        UINT64 read_page = read_hotspot->GuestLinear & ~(static_cast<UINT64>(kPageBytes) - 1ULL);
        same_page_read = (read_page == current.TargetPageBase);
    }

    healthy =
        (delta_emu_success != 0 || delta_ff_shortcut != 0) &&
        delta_emu_failure == 0 &&
        delta_read < 10000 &&
        delta_mtf < 10000;

    strong_suspect =
        delta_emu_success == 0 &&
        delta_ff_shortcut == 0 &&
        delta_emu_failure != 0 &&
        delta_exec >= 1000 &&
        delta_read >= 1000 &&
        (delta_mtf >= 500 || has_pair) &&
        same_page_read;

    suspect =
        !strong_suspect &&
        delta_emu_success == 0 &&
        delta_ff_shortcut == 0 &&
        delta_read >= 1000 &&
        (delta_mtf >= 500 || has_pair);

    if (healthy)
    {
        printf("    PingPong评估: 已缓解\n");
    }
    else if (strong_suspect)
    {
        printf("    PingPong评估: 高度疑似\n");
    }
    else if (suspect)
    {
        printf("    PingPong评估: 疑似\n");
    }
    else
    {
        printf("    PingPong评估: 暂不明显\n");
    }

    printf("    依据: Δexec=%llu  Δread=%llu  Δmtf=%llu  Δemu_ok=%llu  Δemu_fail=%llu  Δff_shortcut=%llu\n",
        delta_exec,
        delta_read,
        delta_mtf,
        delta_emu_success,
        delta_emu_failure,
        delta_ff_shortcut);

    if (has_pair && exec_hotspot && read_hotspot)
    {
        printf("    特征: 同一 RIP 同时出现 EXEC/READ 热点，RIP=%s  READ_GLA=%s\n",
            FormatGameDllAddress(target.GameDllBase, exec_hotspot->Rip).c_str(),
            FormatGameDllAddress(target.GameDllBase, read_hotspot->GuestLinear).c_str());
    }
}

static std::string ClassifyPingPongAssessment(
    const EPT_HOOK_STATS_RESULT& current,
    const EPT_HOOK_STATS_RESULT* baseline)
{
    UINT64 delta_exec = 0;
    UINT64 delta_read = 0;
    UINT64 delta_mtf = 0;
    UINT64 delta_emu_success = 0;
    UINT64 delta_emu_failure = 0;
    UINT64 delta_ff_shortcut = 0;
    const EPT_HOOK_HOTSPOT_RESULT* exec_hotspot = NULL;
    const EPT_HOOK_HOTSPOT_RESULT* read_hotspot = NULL;
    const bool has_pair = TryFindExecReadHotspotPair(current, &exec_hotspot, &read_hotspot);
    bool same_page_read = false;

    if (baseline)
    {
        delta_exec = CounterDelta(current.ExecuteViolations, baseline->ExecuteViolations);
        delta_read = CounterDelta(current.ReadViolations, baseline->ReadViolations);
        delta_mtf = CounterDelta(current.MtfCount, baseline->MtfCount);
        delta_emu_success = CounterDelta(current.EmulationSuccesses, baseline->EmulationSuccesses);
        delta_emu_failure = CounterDelta(current.EmulationFailures, baseline->EmulationFailures);
        delta_ff_shortcut = CounterDelta(current.FfShortcutSuccess, baseline->FfShortcutSuccess);
    }
    else
    {
        delta_exec = current.ExecuteViolations;
        delta_read = current.ReadViolations;
        delta_mtf = current.MtfCount;
        delta_emu_success = current.EmulationSuccesses;
        delta_emu_failure = current.EmulationFailures;
        delta_ff_shortcut = current.FfShortcutSuccess;
    }

    if (read_hotspot)
    {
        UINT64 read_page = read_hotspot->GuestLinear & ~(static_cast<UINT64>(kPageBytes) - 1ULL);
        same_page_read = (read_page == current.TargetPageBase);
    }

    if ((delta_emu_success != 0 || delta_ff_shortcut != 0) &&
        delta_emu_failure == 0 &&
        delta_read < 10000 &&
        delta_mtf < 10000)
    {
        return "已缓解";
    }

    if (delta_emu_success == 0 &&
        delta_ff_shortcut == 0 &&
        delta_emu_failure != 0 &&
        delta_exec >= 1000 &&
        delta_read >= 1000 &&
        (delta_mtf >= 500 || has_pair) &&
        same_page_read)
    {
        return "高度疑似";
    }

    if (delta_emu_success == 0 &&
        delta_ff_shortcut == 0 &&
        delta_read >= 1000 &&
        (delta_mtf >= 500 || has_pair))
    {
        return "疑似";
    }

    return "暂不明显";
}

static void PrintHookStatsResult(const TargetContext& target, const std::string& resolved_text, const EPT_HOOK_STATS_RESULT& result)
{
    printf("[*] Hook统计: %s\n", resolved_text.c_str());
    printf("    TargetPage=0x%p  PatchOffset=0x%llX  PatchSize=0x%llX  Enabled=%u\n",
        reinterpret_cast<void*>(static_cast<ULONG_PTR>(result.TargetPageBase)),
        result.PatchOffset,
        result.PatchSize,
        result.Enabled);
    printf("    PFN: original=0x%llX  fake=0x%llX  TargetCr3=0x%llX\n",
        result.OriginalPfn,
        result.FakePfn,
        result.TargetCr3);
    printf("    Violations: exec=%llu  read=%llu  write=%llu  ctx_miss=%llu  mtf=%llu\n",
        result.ExecuteViolations,
        result.ReadViolations,
        result.WriteViolations,
        result.ContextMismatchViolations,
        result.MtfCount);
    printf("    Emulation: success=%llu  failure=%llu\n",
        result.EmulationSuccesses,
        result.EmulationFailures);
    printf("    FF-shortcut: success=%llu  fail=%llu\n",
        result.FfShortcutSuccess,
        result.FfShortcutFail);
    printf("    FF-raw: ok=%llu  failMode=%llu  failInsn=%llu  failOpcode=%llu  failAddr=%llu  failRead=%llu  failStack=%llu\n",
        result.FfRawSuccess,
        result.FfRawFailMode,
        result.FfRawFailInsnRead,
        result.FfRawFailOpcode,
        result.FfRawFailAddrCalc,
        result.FfRawFailTargetRead,
        result.FfRawFailStack);
    printf("    Last: rip=0x%p  gpa=0x%llX  gla=0x%p  flags=%s\n",
        reinterpret_cast<void*>(static_cast<ULONG_PTR>(result.LastViolationRip)),
        result.LastGuestPhysical,
        reinterpret_cast<void*>(static_cast<ULONG_PTR>(result.LastGuestLinear)),
        DescribeViolationFlags(result.LastViolationFlags).c_str());
    PrintHookHotspots(target, result);
}

static bool QueryAndPrintHookStats(
    const TargetContext& target,
    const std::string& address_token,
    size_t sample_count,
    DWORD interval_ms)
{
    HANDLE device;
    UINT64 resolved_address = 0;
    std::string resolved_text;
    EPT_HOOK_STATS_RESULT first = {};
    EPT_HOOK_STATS_RESULT last = {};
    bool have_first = false;

    if (!EnsureDriverLoaded())
        return false;

    if (!ResolveAddressToken(target.GameDllBase, address_token, &resolved_address, &resolved_text))
    {
        printf("[-] 无法解析地址: %s\n", address_token.c_str());
        return false;
    }

    device = TryOpenDriverHandle();
    if (device == INVALID_HANDLE_VALUE)
    {
        PrintLastError("[-] 打开驱动设备失败，错误码=", GetLastError());
        return false;
    }

    for (size_t i = 0; i < sample_count; ++i)
    {
        EPT_HOOK_STATS_QUERY query = { 0 };
        EPT_HOOK_STATS_RESULT result = { 0 };

        query.ProcessId = target.ProcessId;
        query.VirtualAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(resolved_address));

        if (!QueryHookStatsHandle(device, &query, &result))
        {
            PrintLastError("[-] 查询 Hook 统计失败，错误码=", GetLastError());
            CloseHandle(device);
            return false;
        }

        if (!have_first)
        {
            first = result;
            have_first = true;
        }
        last = result;

        if (sample_count > 1)
            printf("[*] 采样 %zu/%zu\n", i + 1, sample_count);

        PrintHookStatsResult(target, resolved_text, result);

        if (i + 1 < sample_count && interval_ms != 0)
            Sleep(interval_ms);
    }

    if (have_first)
        PrintPingPongAssessment(target, last, sample_count > 1 ? &first : NULL);

    CloseHandle(device);
    return true;
}

static bool QueryAndPrintPagePreflight(
    const TargetContext& target,
    const std::string& address_token)
{
    UINT64 resolved_address = 0;
    std::string resolved_text;
    HookSpec spec = {};
    bool is_wow64 = false;
    PagePreflightReport report = {};

    if (!ResolveAddressToken(target.GameDllBase, address_token, &resolved_address, &resolved_text))
    {
        printf("[-] 无法解析地址: %s\n", address_token.c_str());
        return false;
    }

    (void)QueryProcessBitness(target.ProcessId, &is_wow64);
    spec.Address = resolved_address;
    spec.SourceAddressText = address_token;
    spec.ResolvedAddressText = resolved_text;

    if (!RunPagePreflight(target, resolved_address, is_wow64, &report))
    {
        printf("[*] 安装前预检: %s\n", resolved_text.c_str());
        printf("    [!] 无法读取目标页，跳过预检。\n");
        return false;
    }

    PrintPagePreflightReport(target, spec, report);
    return true;
}

static bool ParseAddressTokensOnly(
    const std::vector<std::string>& input_tokens,
    UINT64 game_dll_base,
    std::vector<HookSpec>* hooks,
    std::string* error_text)
{
    if (!hooks)
        return false;

    std::vector<std::string> tokens = input_tokens;
    StripExeToken(&tokens);

    if (tokens.empty())
        return false;

    hooks->clear();

    for (size_t i = 0; i < tokens.size(); ++i)
    {
        HookSpec spec = {};
        std::string resolved_address_text;

        if (!ResolveAddressToken(game_dll_base, tokens[i], &spec.Address, &resolved_address_text))
        {
            if (error_text)
                *error_text = std::string("地址无法解析: ") + tokens[i] + "。";
            return false;
        }

        spec.SourceAddressText = tokens[i];
        spec.ResolvedAddressText = resolved_address_text;
        hooks->push_back(spec);
    }

    return !hooks->empty();
}

__declspec(noinline) static int TargetFunction()
{
    return 1337;
}

static bool RunSelfTest()
{
    if (!EnsureDriverLoaded())
        return false;

    HANDLE device = TryOpenDriverHandle();
    if (device == INVALID_HANDLE_VALUE)
    {
        PrintLastError("[-] \u6253\u5f00\u9a71\u52a8\u8bbe\u5907\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
        return false;
    }

    printf("[+] \u81ea\u6d4b\u76ee\u6807\u5730\u5740: %p\n", &TargetFunction);
    printf("[+] \u539f\u59cb\u8fd4\u56de\u503c: %d\n", TargetFunction());

    EPT_HOOK_REQUEST req = { 0 };
    UCHAR default_patch[] = { 0xB8, 0x0F, 0x27, 0x00, 0x00, 0xC3 };

    req.ProcessId = GetCurrentProcessId();
    req.VirtualAddress = reinterpret_cast<PVOID>(&TargetFunction);
    memcpy(req.PatchBytes, default_patch, sizeof(default_patch));
    req.PatchSize = static_cast<UINT32>(sizeof(default_patch));

    if (!SendHookRequestHandle(device, &req))
    {
        PrintLastError("[-] \u81ea\u6d4b DeviceIoControl \u8c03\u7528\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
        CloseHandle(device);
        return false;
    }

    printf("[+] \u81ea\u6d4b Hook \u5b89\u88c5\u6210\u529f\u3002\n");
    printf("[+] Hook \u540e\u8fd4\u56de\u503c: %d\n", TargetFunction());
    CloseHandle(device);
    return true;
}

static std::vector<std::string> TokenizeLine(const std::string& line)
{
    std::vector<std::string> tokens;
    std::istringstream stream(line);
    std::string token;

    while (stream >> token)
    {
        tokens.push_back(token);
    }

    return tokens;
}

static void StripExeToken(std::vector<std::string>* tokens)
{
    if (!tokens || tokens->empty())
        return;

    if (EndsWithInsensitive((*tokens)[0], ".exe"))
    {
        tokens->erase(tokens->begin());
    }
}

static void PrintInteractiveHelp(const char* exe_name)
{
    printf("\u53ef\u7528\u547d\u4ee4:\n");
    printf("  %s <\u504f\u79fb1> <\u8865\u4e011> [<\u504f\u79fb2> <\u8865\u4e012> ...]\n", exe_name);
    printf("  <\u504f\u79fb1> <\u8865\u4e011> [<\u504f\u79fb2> <\u8865\u4e012> ...]\n");
    printf("    \u7a0b\u5e8f\u4f1a\u81ea\u52a8\u67e5\u627e war3.exe / 16_war3.exe\uff0c\u7136\u540e\u8bfb\u53d6\u8be5\u8fdb\u7a0b\u7684 game.dll \u57fa\u5740\u3002\n");
    printf("    \u4f60\u8f93\u5165\u7684\u5730\u5740\u4f1a\u88ab\u5f53\u6210 game.dll \u7684\u504f\u79fb\u3002\n");
    printf("  \u652f\u6301\u7684\u5730\u5740\u5199\u6cd5:\n");
    printf("    game.dll+0x3A20DD\n");
    printf("    0x3A20DD\n");
    printf("    0x6F3A20DD   (\u65e7\u7248 game.dll \u7edd\u5bf9\u5730\u5740\uff0c\u4f1a\u81ea\u52a8\u6362\u7b97\u6210\u504f\u79fb)\n");
    printf("  \u5176\u4ed6\u547d\u4ee4:\n");
    printf("    auto      \u91cd\u65b0\u67e5\u627e war3.exe / 16_war3.exe \u548c game.dll\n");
    printf("    load      \u91cd\u65b0\u5c1d\u8bd5\u52a0\u8f7d\u9a71\u52a8\n");
    printf("    status    \u67e5\u770b\u5f53\u524d\u76ee\u6807\u8fdb\u7a0b\u548c game.dll \u57fa\u5740\n");
    printf("    scan <\u5730\u5740>\n");
    printf("              \u5b89\u88c5 Hook \u524d\u9884\u626b\u63cf\u8fd9\u5f20\u9875\uff0c\u627e\u51fa\u540c\u9875 jump table / lookup table / \u95f4\u63a5 jmp/call \u7b49\u9ad8\u98ce\u9669\u7279\u5f81\n");
    printf("    stats <\u5730\u5740> [\u6b21\u6570] [\u95f4\u9694\u6beb\u79d2]\n");
    printf("              \u67e5\u8be2\u6307\u5b9a Hook \u9875\u7684 EPT \u7edf\u8ba1\uff0c\u5e76\u663e\u793a\u6700\u70ed\u7684 RIP/GLA \u70b9\n");
    printf("    unhook <\u5730\u57401> [\u5730\u57402 ...]\n");
    printf("              \u6309\u5730\u5740\u5378\u8f7d\u4e00\u4e2a\u6216\u591a\u4e2a EPT Hook\uff1b\u540c\u9875\u591a patch \u4f1a\u6309\u7cbe\u786e\u504f\u79fb\u5220\u9664\n");
    printf("    unhookall\n");
    printf("              \u4e00\u952e\u5378\u8f7d\u5168\u90e8 EPT Hook\n");
    printf("    unhookpage <\u5730\u57401> [\u5730\u57402 ...]\n");
    printf("              \u6309\u9875\u5378\u8f7d\uff0c\u76f4\u63a5\u6444\u6389\u8be5 4KB \u9875\u4e0a\u7684\u5168\u90e8 EPT Hook\uff0c\u9002\u5408\u7d27\u6025\u6b62\u8840 ping-pong\n");
    printf("    autofuse <\u5730\u5740> [\u6b21\u6570] [\u95f4\u9694\u6beb\u79d2] [\u9608\u503c]\n");
    printf("              \u8fde\u7eed\u91c7\u6837 stats\uff0c\u5982 read/mtf \u589e\u91cf\u8d85\u8fc7\u9608\u503c\uff0c\u81ea\u52a8\u6267\u884c unhookpage\n");
    printf("    unloadhv / unload\n");
    printf("              \u5148\u5378\u8f7d\u5168\u90e8 EPT Hook\uff0c\u518d\u5b89\u5168\u505c\u6b62 Hypervisor \u9a71\u52a8\n");
    printf("    selftest  \u8fd0\u884c\u5185\u7f6e\u81ea\u6d4b\n");
    printf("    help      \u663e\u793a\u5e2e\u52a9\n");
    printf("    exit      \u9000\u51fa\u7a0b\u5e8f\n");
}

static bool CollectHookOverlapWarnings(
    const std::vector<HookSpec>& hooks,
    std::vector<HookOverlapWarning>* warnings)
{
    if (!warnings)
        return false;

    warnings->clear();

    for (size_t i = 0; i < hooks.size(); ++i)
    {
        UINT64 first_page = hooks[i].Address & ~static_cast<UINT64>(kPageBytes - 1);
        UINT64 first_start = hooks[i].Address;
        UINT64 first_end = first_start + hooks[i].PatchBytes.size() - 1;

        for (size_t j = i + 1; j < hooks.size(); ++j)
        {
            UINT64 second_page = hooks[j].Address & ~static_cast<UINT64>(kPageBytes - 1);
            UINT64 second_start = hooks[j].Address;
            UINT64 second_end = second_start + hooks[j].PatchBytes.size() - 1;

            if (first_page != second_page)
                continue;

            if (first_end < second_start || second_end < first_start)
                continue;

            HookOverlapWarning warning = {};
            warning.FirstIndex = i;
            warning.SecondIndex = j;
            warning.PageBase = first_page;
            warning.FirstStart = first_start;
            warning.FirstEnd = first_end;
            warning.SecondStart = second_start;
            warning.SecondEnd = second_end;
            warnings->push_back(warning);
        }
    }

    return !warnings->empty();
}

static void PrintHookOverlapWarnings(
    const TargetContext& target,
    const std::vector<HookSpec>& hooks)
{
    std::vector<HookOverlapWarning> warnings;

    if (!CollectHookOverlapWarnings(hooks, &warnings))
        return;

    printf("[!] \u68c0\u6d4b\u5230 %zu \u7ec4\u540c\u9875 patch \u8303\u56f4\u91cd\u53e0\uff1a\n", warnings.size());
    for (size_t i = 0; i < warnings.size(); ++i)
    {
        const HookOverlapWarning& warning = warnings[i];
        const HookSpec& first = hooks[warning.FirstIndex];
        const HookSpec& second = hooks[warning.SecondIndex];

        printf("    %s  [%s .. %s]\n",
            first.ResolvedAddressText.c_str(),
            FormatGameDllAddress(target.GameDllBase, warning.FirstStart).c_str(),
            FormatGameDllAddress(target.GameDllBase, warning.FirstEnd).c_str());
        printf("    %s  [%s .. %s]\n",
            second.ResolvedAddressText.c_str(),
            FormatGameDllAddress(target.GameDllBase, warning.SecondStart).c_str(),
            FormatGameDllAddress(target.GameDllBase, warning.SecondEnd).c_str());
        printf("    Page=%s\n",
            FormatGameDllAddress(target.GameDllBase, warning.PageBase).c_str());
    }
}

static bool ParseHookTokens(
    const std::vector<std::string>& input_tokens,
    UINT64 game_dll_base,
    std::vector<HookSpec>* hooks,
    std::string* error_text)
{
    if (!hooks)
        return false;

    std::vector<std::string> tokens = input_tokens;
    StripExeToken(&tokens);

    if (tokens.empty())
        return false;

    if (tokens.size() < 2 || (tokens.size() % 2) != 0)
        return false;

    hooks->clear();

    for (size_t i = 0; i < tokens.size(); i += 2)
    {
        HookSpec spec = { 0 };
        std::vector<UCHAR> patch_bytes;
        std::string resolved_address_text;

        if (!ParsePatchHex(tokens[i + 1].c_str(), &patch_bytes))
        {
            if (error_text)
                *error_text = std::string("\u8865\u4e01\u5b57\u8282\u4e32\u683c\u5f0f\u4e0d\u6b63\u786e: ") + tokens[i + 1];
            return false;
        }

        if (patch_bytes.empty() || patch_bytes.size() > 16)
        {
            if (error_text)
                *error_text = "\u8865\u4e01\u957f\u5ea6\u5fc5\u987b\u5728 1 \u5230 16 \u5b57\u8282\u4e4b\u95f4\u3002";
            return false;
        }

        if (!ResolveAddressToken(game_dll_base, tokens[i], &spec.Address, &resolved_address_text))
        {
            if (error_text)
                *error_text = std::string("\u5730\u5740\u65e0\u6cd5\u89e3\u6790: ") + tokens[i] + "\u3002\u8bf7\u786e\u8ba4\u76ee\u6807\u8fdb\u7a0b\u5df2\u52a0\u8f7d game.dll\uff0c\u5e76\u4e14\u8fd9\u91cc\u586b\u7684\u662f\u504f\u79fb\u3002";
            return false;
        }

        spec.PatchBytes.swap(patch_bytes);
        spec.SourceAddressText = tokens[i];
        spec.ResolvedAddressText = resolved_address_text;
        hooks->push_back(spec);
    }

    return !hooks->empty();
}

static bool ExecuteHookBatch(const TargetContext& target, const std::vector<HookSpec>& hooks)
{
    if (hooks.empty())
        return false;

    if (!EnsureDriverLoaded())
        return false;

    HANDLE device = TryOpenDriverHandle();
    if (device == INVALID_HANDLE_VALUE)
    {
        PrintLastError("[-] \u6253\u5f00\u9a71\u52a8\u8bbe\u5907\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
        return false;
    }

    bool is_wow64 = false;
    std::vector<UINT64> scanned_pages;
    if (QueryProcessBitness(target.ProcessId, &is_wow64))
    {
        printf("[*] \u76ee\u6807\u8fdb\u7a0b: %s (PID=%lu, %s)\n",
            target.ImageName.c_str(),
            target.ProcessId,
            is_wow64 ? "WOW64 / 32\u4f4d" : "\u539f\u751f x64");
    }
    else
    {
        printf("[!] \u65e0\u6cd5\u67e5\u8be2\u76ee\u6807\u8fdb\u7a0b\u4f4d\u6570\uff0cPID=%lu\n", target.ProcessId);
    }

    printf("[*] game.dll \u57fa\u5740: 0x%p\n", reinterpret_cast<void*>(static_cast<ULONG_PTR>(target.GameDllBase)));
    PrintHookBatchRegionSummary(target, hooks);
    PrintHookOverlapWarnings(target, hooks);

    bool batch_mode = false;
    bool batch_end_ok = true;
    if (hooks.size() > 1)
    {
        if (SendSimpleIoctlHandle(device, IOCTL_HV_EPT_BATCH_BEGIN))
        {
            batch_mode = true;
            printf("[*] \u5df2\u542f\u7528\u6279\u91cf EPT \u5237\u65b0\uff1a\u672c\u6b21\u6279\u91cf\u5b89\u88c5\u7ed3\u675f\u540e\u7edf\u4e00\u540c\u6b65\u6240\u6709\u6838\u5fc3\u3002\n");
        }
        else
        {
            printf("[!] \u9a71\u52a8\u672a\u5f00\u542f\u6279\u91cf EPT \u5237\u65b0\uff0c\u56de\u9000\u5230\u9010\u4e2a Hook \u5237\u65b0\u3002\n");
        }
    }

    size_t success_count = 0;
    for (size_t i = 0; i < hooks.size(); ++i)
    {
        const HookSpec& spec = hooks[i];
        EPT_HOOK_REQUEST req = { 0 };
        UINT64 page_base = spec.Address & ~static_cast<UINT64>(kPageBytes - 1);

        req.ProcessId = target.ProcessId;
        req.VirtualAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(spec.Address));
        req.PatchSize = static_cast<UINT32>(spec.PatchBytes.size());
        memcpy(req.PatchBytes, spec.PatchBytes.data(), spec.PatchBytes.size());

        printf("[*] \u5b89\u88c5 Hook %zu/%zu: %s -> ", i + 1, hooks.size(), spec.ResolvedAddressText.c_str());
        PrintPatch(req.PatchBytes, req.PatchSize);
        printf("  [\u8f93\u5165=%s]\n", spec.SourceAddressText.c_str());

        if (std::find(scanned_pages.begin(), scanned_pages.end(), page_base) == scanned_pages.end())
        {
            PagePreflightReport report = {};
            if (RunPagePreflight(target, spec.Address, is_wow64, &report))
                PrintPagePreflightReport(target, spec, report);
            else
                printf("[*] 安装前预检: %s\n    [!] 无法读取目标页，跳过预检。\n", spec.ResolvedAddressText.c_str());

            scanned_pages.push_back(page_base);
        }

        if (!SendHookRequestHandle(device, &req))
        {
            PrintLastError("[-] DeviceIoControl \u8c03\u7528\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
            continue;
        }

        ++success_count;
        printf("[+] Hook \u5b89\u88c5\u6210\u529f\u3002\n");
        InstallPreScannedFastRulesForHook(device, target, spec, is_wow64);
        printf("[*] 可继续输入: stats %s 5 200\n", spec.SourceAddressText.c_str());
    }

    if (batch_mode)
    {
        batch_end_ok = SendSimpleIoctlHandle(device, IOCTL_HV_EPT_BATCH_END);
        if (batch_end_ok)
            printf("[*] \u6279\u91cf EPT \u5237\u65b0\u5df2\u5b8c\u6210\u3002\n");
        else
            PrintLastError("[!] \u6279\u91cf EPT \u5237\u65b0\u7ed3\u675f\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
    }

    CloseHandle(device);
    printf("[*] \u672c\u6b21\u7ed3\u679c: %zu/%zu \u6210\u529f\u3002\n", success_count, hooks.size());
    return success_count == hooks.size() && batch_end_ok;
}

static bool ExecuteUnhookBatch(const TargetContext& target, const std::vector<HookSpec>& hooks)
{
    if (hooks.empty())
        return false;

    if (!EnsureDriverLoaded())
        return false;

    HANDLE device = TryOpenDriverHandle();
    if (device == INVALID_HANDLE_VALUE)
    {
        PrintLastError("[-] 打开驱动设备失败，错误码=", GetLastError());
        return false;
    }

    bool batch_mode = false;
    bool batch_end_ok = true;
    if (hooks.size() > 1)
    {
        if (SendSimpleIoctlHandle(device, IOCTL_HV_EPT_BATCH_BEGIN))
        {
            batch_mode = true;
            printf("[*] 已启用批量 EPT 刷新：本次批量卸载结束后统一同步所有核心。\n");
        }
    }

    size_t success_count = 0;
    for (size_t i = 0; i < hooks.size(); ++i)
    {
        const HookSpec& spec = hooks[i];
        EPT_HOOK_UNHOOK_REQUEST req = {};

        req.ProcessId = target.ProcessId;
        req.VirtualAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(spec.Address));

        printf("[*] 卸载 Hook %zu/%zu: %s  [输入=%s]\n",
            i + 1,
            hooks.size(),
            spec.ResolvedAddressText.c_str(),
            spec.SourceAddressText.c_str());

        if (!SendUnhookRequestHandle(device, &req))
        {
            PrintLastError("[-] 卸载 Hook 失败，错误码=", GetLastError());
            continue;
        }

        ++success_count;
        printf("[+] Hook 卸载成功。\n");
    }

    if (batch_mode)
    {
        batch_end_ok = SendSimpleIoctlHandle(device, IOCTL_HV_EPT_BATCH_END);
        if (batch_end_ok)
            printf("[*] 批量 EPT 刷新已完成。\n");
        else
            PrintLastError("[!] 批量 EPT 刷新结束失败，错误码=", GetLastError());
    }

    CloseHandle(device);
    printf("[*] 本次结果: %zu/%zu 成功。\n", success_count, hooks.size());
    return success_count == hooks.size() && batch_end_ok;
}

static bool ExecuteUnhookAll()
{
    if (!EnsureDriverLoaded())
        return false;

    HANDLE device = TryOpenDriverHandle();
    if (device == INVALID_HANDLE_VALUE)
    {
        PrintLastError("[-] 打开驱动设备失败，错误码=", GetLastError());
        return false;
    }

    if (!SendSimpleIoctlHandle(device, IOCTL_HV_EPT_UNHOOK_ALL))
    {
        PrintLastError("[-] 卸载全部 EPT Hook 失败，错误码=", GetLastError());
        CloseHandle(device);
        return false;
    }

    CloseHandle(device);
    printf("[+] 已卸载全部 EPT Hook。\n");
    return true;
}

static bool ExecuteUnhookPageBatch(const TargetContext& target, const std::vector<HookSpec>& hooks)
{
    if (hooks.empty())
        return false;

    if (!EnsureDriverLoaded())
        return false;

    HANDLE device = TryOpenDriverHandle();
    if (device == INVALID_HANDLE_VALUE)
    {
        PrintLastError("[-] 打开驱动设备失败，错误码=", GetLastError());
        return false;
    }

    bool batch_mode = false;
    bool batch_end_ok = true;
    if (hooks.size() > 1)
    {
        if (SendSimpleIoctlHandle(device, IOCTL_HV_EPT_BATCH_BEGIN))
        {
            batch_mode = true;
            printf("[*] 已启用批量 EPT 刷新：本次整页卸载结束后统一同步所有核心。\n");
        }
    }

    std::vector<UINT64> removed_pages;
    size_t success_count = 0;
    for (size_t i = 0; i < hooks.size(); ++i)
    {
        const HookSpec& spec = hooks[i];
        UINT64 page_base = spec.Address & ~static_cast<UINT64>(kPageBytes - 1);
        EPT_HOOK_UNHOOK_REQUEST req = {};

        if (std::find(removed_pages.begin(), removed_pages.end(), page_base) != removed_pages.end())
            continue;

        req.ProcessId = target.ProcessId;
        req.VirtualAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(spec.Address));

        printf("[*] 整页卸载 %zu/%zu: %s  [Page=%s]\n",
            i + 1,
            hooks.size(),
            spec.ResolvedAddressText.c_str(),
            FormatGameDllAddress(target.GameDllBase, page_base).c_str());

        if (!SendUnhookPageRequestHandle(device, &req))
        {
            PrintLastError("[-] 整页卸载 Hook 失败，错误码=", GetLastError());
            continue;
        }

        removed_pages.push_back(page_base);
        ++success_count;
        printf("[+] 已卸载该页上的全部 EPT Hook。\n");
    }

    if (batch_mode)
    {
        batch_end_ok = SendSimpleIoctlHandle(device, IOCTL_HV_EPT_BATCH_END);
        if (batch_end_ok)
            printf("[*] 批量 EPT 刷新已完成。\n");
        else
            PrintLastError("[!] 批量 EPT 刷新结束失败，错误码=", GetLastError());
    }

    CloseHandle(device);
    printf("[*] 本次结果: %zu/%zu 页成功。\n", success_count, removed_pages.size());
    return success_count != 0 && success_count == removed_pages.size() && batch_end_ok;
}

static bool ExecuteAutoFuse(
    const TargetContext& target,
    const std::string& address_token,
    size_t sample_count,
    DWORD interval_ms,
    UINT64 threshold)
{
    HANDLE device;
    UINT64 resolved_address = 0;
    std::string resolved_text;
    EPT_HOOK_STATS_QUERY query = {};
    EPT_HOOK_STATS_RESULT first = {};
    EPT_HOOK_STATS_RESULT current = {};
    UINT64 delta_exec = 0;
    UINT64 delta_read = 0;
    UINT64 delta_mtf = 0;
    HookSpec hook = {};

    if (!EnsureDriverLoaded())
        return false;

    if (!ResolveAddressToken(target.GameDllBase, address_token, &resolved_address, &resolved_text))
    {
        printf("[-] 无法解析地址: %s\n", address_token.c_str());
        return false;
    }

    device = TryOpenDriverHandle();
    if (device == INVALID_HANDLE_VALUE)
    {
        PrintLastError("[-] 打开驱动设备失败，错误码=", GetLastError());
        return false;
    }

    query.ProcessId = target.ProcessId;
    query.VirtualAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(resolved_address));

    for (size_t i = 0; i < sample_count; ++i)
    {
        if (!QueryHookStatsHandle(device, &query, &current))
        {
            PrintLastError("[-] 查询 Hook 统计失败，错误码=", GetLastError());
            CloseHandle(device);
            return false;
        }

        if (i == 0)
            first = current;

        printf("[*] autofuse 采样 %zu/%zu\n", i + 1, sample_count);
        PrintHookStatsResult(target, resolved_text, current);

        if (i + 1 < sample_count && interval_ms != 0)
            Sleep(interval_ms);
    }

    CloseHandle(device);

    delta_exec = current.ExecuteViolations - first.ExecuteViolations;
    delta_read = current.ReadViolations - first.ReadViolations;
    delta_mtf = current.MtfCount - first.MtfCount;

    printf("[*] autofuse 增量: exec=%llu  read=%llu  mtf=%llu  阈值=%llu\n",
        delta_exec,
        delta_read,
        delta_mtf,
        threshold);
    PrintPingPongAssessment(target, current, &first);

    if (delta_read < threshold && delta_mtf < threshold)
    {
        printf("[*] 未达到熔断阈值，本次不自动卸载。\n");
        return true;
    }

    printf("[!] 检测到疑似 EPT ping-pong，开始整页熔断卸载。\n");
    hook.Address = resolved_address;
    hook.SourceAddressText = address_token;
    hook.ResolvedAddressText = resolved_text;
    return ExecuteUnhookPageBatch(target, std::vector<HookSpec>(1, hook));
}

static bool ExecuteJudgeAll(
    const TargetContext& target,
    size_t sample_count,
    DWORD interval_ms)
{
    HANDLE device;
    size_t checked_count = 0;
    size_t suspicious_count = 0;
    std::vector<SessionInstalledHook> hooks;

    if (!EnsureDriverLoaded())
        return false;

    for (size_t i = 0; i < g_session_installed_hooks.size(); ++i)
    {
        if (g_session_installed_hooks[i].ProcessId == target.ProcessId)
            hooks.push_back(g_session_installed_hooks[i]);
    }

    if (hooks.empty())
    {
        printf("[*] 当前会话里没有记录到已安装的 EPT Hook，无法自动判断。\n");
        return true;
    }

    device = TryOpenDriverHandle();
    if (device == INVALID_HANDLE_VALUE)
    {
        PrintLastError("[-] 打开驱动设备失败，错误码=", GetLastError());
        return false;
    }

    printf("[*] 自动巡检 %zu 个已安装 Hook，开始智能判断 ping-pong...\n", hooks.size());

    for (size_t i = 0; i < hooks.size(); ++i)
    {
        EPT_HOOK_STATS_QUERY query = {};
        EPT_HOOK_STATS_RESULT first = {};
        EPT_HOOK_STATS_RESULT current = {};
        bool have_first = false;

        query.ProcessId = target.ProcessId;
        query.VirtualAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(hooks[i].Address));

        for (size_t sample_index = 0; sample_index < sample_count; ++sample_index)
        {
            if (!QueryHookStatsHandle(device, &query, &current))
            {
                PrintLastError("[-] 查询 Hook 统计失败，错误码=", GetLastError());
                CloseHandle(device);
                return false;
            }

            if (!have_first)
            {
                first = current;
                have_first = true;
            }

            if (sample_index + 1 < sample_count && interval_ms != 0)
                Sleep(interval_ms);
        }

        std::string verdict = ClassifyPingPongAssessment(current, sample_count > 1 ? &first : NULL);
        if (verdict == "高度疑似" || verdict == "疑似")
            ++suspicious_count;

        ++checked_count;
        printf("    [%zu/%zu] %s -> %s\n",
            i + 1,
            hooks.size(),
            hooks[i].ResolvedAddressText.c_str(),
            verdict.c_str());
    }

    CloseHandle(device);
    printf("[*] 自动判断完成: checked=%zu  suspicious=%zu\n", checked_count, suspicious_count);
    return true;
}

static bool ProcessCommandTokens(
    std::vector<std::string> tokens,
    const char* exe_name,
    TargetContext* target)
{
    if (!target)
        return true;

    StripExeToken(&tokens);
    if (tokens.empty())
        return true;

    std::string command = ToLowerAscii(tokens[0]);

    if (command == "help" || command == "?")
    {
        PrintInteractiveHelp(exe_name);
        return true;
    }

    if (command == "exit" || command == "quit")
    {
        return false;
    }

    if (command == "load")
    {
        EnsureDriverLoaded();
        return true;
    }

    if (command == "status")
    {
        HANDLE device = TryOpenDriverHandle();
        if (device != INVALID_HANDLE_VALUE)
        {
            printf("[+] \u9a71\u52a8\u8bbe\u5907\u53ef\u7528: %s\n", kDevicePath);
            CloseHandle(device);
        }
        else
        {
            PrintLastError("[-] \u9a71\u52a8\u8bbe\u5907\u5c1a\u672a\u5c31\u7eea\uff0c\u9519\u8bef\u7801=", GetLastError());
        }

        if (!RefreshTargetContext(target, false))
        {
            printf("[*] \u5f53\u524d\u6ca1\u6709\u627e\u5230\u5df2\u52a0\u8f7d game.dll \u7684 war3.exe / 16_war3.exe\u3002\n");
            return true;
        }

        printf("[*] \u5f53\u524d\u76ee\u6807\u8fdb\u7a0b: %s\n", target->ImageName.c_str());
        printf("[*] \u5f53\u524d\u76ee\u6807 PID: %lu\n", target->ProcessId);

        bool is_wow64 = false;
        if (QueryProcessBitness(target->ProcessId, &is_wow64))
        {
            printf("[*] \u8fdb\u7a0b\u4f4d\u6570: %s\n", is_wow64 ? "WOW64 / 32\u4f4d" : "\u539f\u751f x64");
        }
        printf("[*] game.dll \u57fa\u5740: 0x%p\n", reinterpret_cast<void*>(static_cast<ULONG_PTR>(target->GameDllBase)));
        return true;
    }

    if (command == "stats")
    {
        unsigned long long sample_count_value = 1;
        unsigned long long interval_ms_value = 0;

        if (tokens.size() < 2 || tokens.size() > 4)
        {
            printf("[-] 用法: stats <地址> [次数] [间隔毫秒]\n");
            return true;
        }

        if (tokens.size() >= 3 && !ParseUnsignedValue(tokens[2].c_str(), &sample_count_value))
        {
            printf("[-] 次数参数无效: %s\n", tokens[2].c_str());
            return true;
        }

        if (tokens.size() >= 4 && !ParseUnsignedValue(tokens[3].c_str(), &interval_ms_value))
        {
            printf("[-] 间隔毫秒参数无效: %s\n", tokens[3].c_str());
            return true;
        }

        if (sample_count_value == 0)
            sample_count_value = 1;

        if (!RefreshTargetContext(target, true))
            return true;

        (void)QueryAndPrintHookStats(
            *target,
            tokens[1],
            static_cast<size_t>(sample_count_value),
            static_cast<DWORD>(interval_ms_value));
        return true;
    }

    if (command == "unhook")
    {
        if (tokens.size() < 2)
        {
            printf("[-] 用法: unhook <地址1> [地址2 ...]\n");
            return true;
        }

        if (!RefreshTargetContext(target, true))
            return true;

        std::vector<std::string> address_tokens(tokens.begin() + 1, tokens.end());
        std::vector<HookSpec> hooks;
        std::string parse_error;
        if (!ParseAddressTokensOnly(address_tokens, target->GameDllBase, &hooks, &parse_error))
        {
            if (!parse_error.empty())
                printf("[-] %s\n", parse_error.c_str());
            return true;
        }

        (void)ExecuteUnhookBatch(*target, hooks);
        return true;
    }

    if (command == "unhookall")
    {
        (void)ExecuteUnhookAll();
        return true;
    }

    if (command == "unhookpage")
    {
        if (tokens.size() < 2)
        {
            printf("[-] 用法: unhookpage <地址1> [地址2 ...]\n");
            return true;
        }

        if (!RefreshTargetContext(target, true))
            return true;

        std::vector<std::string> address_tokens(tokens.begin() + 1, tokens.end());
        std::vector<HookSpec> hooks;
        std::string parse_error;
        if (!ParseAddressTokensOnly(address_tokens, target->GameDllBase, &hooks, &parse_error))
        {
            if (!parse_error.empty())
                printf("[-] %s\n", parse_error.c_str());
            return true;
        }

        (void)ExecuteUnhookPageBatch(*target, hooks);
        return true;
    }

    if (command == "autofuse")
    {
        unsigned long long sample_count_value = 5;
        unsigned long long interval_ms_value = 200;
        unsigned long long threshold_value = 5000;

        if (tokens.size() < 2 || tokens.size() > 5)
        {
            printf("[-] 用法: autofuse <地址> [次数] [间隔毫秒] [阈值]\n");
            return true;
        }

        if (tokens.size() >= 3 && !ParseUnsignedValue(tokens[2].c_str(), &sample_count_value))
        {
            printf("[-] 次数参数无效: %s\n", tokens[2].c_str());
            return true;
        }

        if (tokens.size() >= 4 && !ParseUnsignedValue(tokens[3].c_str(), &interval_ms_value))
        {
            printf("[-] 间隔毫秒参数无效: %s\n", tokens[3].c_str());
            return true;
        }

        if (tokens.size() >= 5 && !ParseUnsignedValue(tokens[4].c_str(), &threshold_value))
        {
            printf("[-] 阈值参数无效: %s\n", tokens[4].c_str());
            return true;
        }

        if (sample_count_value == 0)
            sample_count_value = 1;

        if (!RefreshTargetContext(target, true))
            return true;

        (void)ExecuteAutoFuse(
            *target,
            tokens[1],
            static_cast<size_t>(sample_count_value),
            static_cast<DWORD>(interval_ms_value),
            static_cast<UINT64>(threshold_value));
        return true;
    }

    if (command == "unloadhv" || command == "unload")
    {
        (void)StopDriverServiceSafely();
        return true;
    }

    if (command == "scan")
    {
        if (tokens.size() != 2)
        {
            printf("[-] 用法: scan <地址>\n");
            return true;
        }

        if (!RefreshTargetContext(target, true))
            return true;

        (void)QueryAndPrintPagePreflight(*target, tokens[1]);
        return true;
    }

    if (command == "auto")
    {
        RefreshTargetContext(target, true);
        return true;
    }

    if (command == "selftest")
    {
        RunSelfTest();
        return true;
    }

    if (!RefreshTargetContext(target, true))
    {
        return true;
    }

    std::vector<HookSpec> hooks;
    std::string parse_error;
    if (!ParseHookTokens(tokens, target->GameDllBase, &hooks, &parse_error))
    {
        if (!parse_error.empty())
        {
            printf("[-] %s\n", parse_error.c_str());
        }
        printf("[-] \u8f93\u5165\u683c\u5f0f\u4e0d\u6b63\u786e\u3002\u7528\u6cd5\u5982\u4e0b:\n");
        printf("    %s <\u504f\u79fb1> <\u8865\u4e011> [<\u504f\u79fb2> <\u8865\u4e012> ...]\n", exe_name);
        printf("    \u4f8b\u5982: 0x3A20DD EB32 0x285CBC 742A\n");
        return true;
    }

    (void)ExecuteHookBatch(*target, hooks);
    return true;
}

int main(int argc, char* argv[])
{
    TargetContext target = { 0 };

    printf("=== Ophion \u4ea4\u4e92\u5de5\u5177 ===\n");
    printf("[*] \u6b63\u5728\u542f\u7528 SeDebugPrivilege...\n");
    if (EnablePrivilege(L"SeDebugPrivilege"))
    {
        printf("[+] SeDebugPrivilege \u542f\u7528\u6210\u529f\u3002\n");
    }
    else
    {
        printf("[!] SeDebugPrivilege \u542f\u7528\u5931\u8d25\uff0c\u67d0\u4e9b\u8fdb\u7a0b\u6216\u6a21\u5757\u53ef\u80fd\u65e0\u6cd5\u8bbf\u95ee\u3002\n");
    }
    printf("[*] \u6b63\u5728\u68c0\u67e5\u5e76\u52a0\u8f7d\u9a71\u52a8...\n");
    EnsureDriverLoaded();
    RefreshTargetContext(&target, true);
    PrintInteractiveHelp(argv[0]);

    if (argc > 1)
    {
        std::vector<std::string> initial_tokens;
        for (int i = 1; i < argc; ++i)
        {
            initial_tokens.push_back(argv[i]);
        }

        if (!ProcessCommandTokens(initial_tokens, argv[0], &target))
            return 0;
    }

    for (;;)
    {
        if (target.ProcessId != 0)
        {
            printf("ophion[%s:%lu][game.dll=0x%p]> ",
                target.ImageName.c_str(),
                target.ProcessId,
                reinterpret_cast<void*>(static_cast<ULONG_PTR>(target.GameDllBase)));
        }
        else
        {
            printf("ophion> ");
        }

        std::string line;
        if (!std::getline(std::cin, line))
            break;

        std::vector<std::string> tokens = TokenizeLine(line);
        if (!ProcessCommandTokens(tokens, argv[0], &target))
            break;
    }

    return 0;
}
