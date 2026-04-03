#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#define IOCTL_BASE 0x800
#define IOCTL_HV_EPT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _EPT_HOOK_REQUEST {
    UINT32 ProcessId;
    PVOID  VirtualAddress;
    UCHAR  PatchBytes[16];
    UINT32 PatchSize;
} EPT_HOOK_REQUEST, *PEPT_HOOK_REQUEST;

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

static const char* kDriverServiceName = "Ophion";
static const char* kDriverDisplayName = "Ophion Hypervisor";
static const char* kDevicePath = "\\\\.\\Ophion";
static const wchar_t* kPreferredTargetNames[] = { L"war3.exe", L"16_war3.exe" };
static const wchar_t* kDefaultModuleName = L"game.dll";
static const UINT64 kLegacyGameDllBase = 0x6F000000ULL;

static bool TryGetModuleBase(DWORD pid, const wchar_t* module_name, UINT64* base_address, std::string* resolved_name);

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

static bool EnsureDriverLoaded()
{
    HANDLE existing_device = TryOpenDriverHandle();
    if (existing_device != INVALID_HANDLE_VALUE)
    {
        printf("[+] \u9a71\u52a8\u5df2\u7ecf\u52a0\u8f7d\uff0c\u8bbe\u5907\u5df2\u5c31\u7eea: %s\n", kDevicePath);
        CloseHandle(existing_device);
        return true;
    }

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
    printf("    selftest  \u8fd0\u884c\u5185\u7f6e\u81ea\u6d4b\n");
    printf("    help      \u663e\u793a\u5e2e\u52a9\n");
    printf("    exit      \u9000\u51fa\u7a0b\u5e8f\n");
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

    size_t success_count = 0;
    for (size_t i = 0; i < hooks.size(); ++i)
    {
        const HookSpec& spec = hooks[i];
        EPT_HOOK_REQUEST req = { 0 };

        req.ProcessId = target.ProcessId;
        req.VirtualAddress = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(spec.Address));
        req.PatchSize = static_cast<UINT32>(spec.PatchBytes.size());
        memcpy(req.PatchBytes, spec.PatchBytes.data(), spec.PatchBytes.size());

        printf("[*] \u5b89\u88c5 Hook %zu/%zu: %s -> ", i + 1, hooks.size(), spec.ResolvedAddressText.c_str());
        PrintPatch(req.PatchBytes, req.PatchSize);
        printf("  [\u8f93\u5165=%s]\n", spec.SourceAddressText.c_str());

        if (!SendHookRequestHandle(device, &req))
        {
            PrintLastError("[-] DeviceIoControl \u8c03\u7528\u5931\u8d25\uff0c\u9519\u8bef\u7801=", GetLastError());
            continue;
        }

        ++success_count;
        printf("[+] Hook \u5b89\u88c5\u6210\u529f\u3002\n");
    }

    CloseHandle(device);
    printf("[*] \u672c\u6b21\u7ed3\u679c: %zu/%zu \u6210\u529f\u3002\n", success_count, hooks.size());
    return success_count == hooks.size();
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
