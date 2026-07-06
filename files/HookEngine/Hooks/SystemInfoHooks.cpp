#include "SystemInfoHooks.h"
#include "../HookEngine.h"
#include <sstream>
#include <iomanip>

// ========== 原始函数指针 ==========
static void (WINAPI *Real_GetSystemInfo)(LPSYSTEM_INFO) = GetSystemInfo;
static void (WINAPI *Real_GetNativeSystemInfo)(LPSYSTEM_INFO) = GetNativeSystemInfo;
static void (WINAPI *Real_GetSystemTime)(LPSYSTEMTIME) = GetSystemTime;
static void (WINAPI *Real_GetLocalTime)(LPSYSTEMTIME) = GetLocalTime;
static DWORD (WINAPI *Real_GetVersion)() = GetVersion;
static BOOL (WINAPI *Real_GetVersionExW)(LPOSVERSIONINFOW) = GetVersionExW;
static BOOL (WINAPI *Real_GetVersionExA)(LPOSVERSIONINFOA) = GetVersionExA;

static BOOL (WINAPI *Real_GetComputerNameW)(LPWSTR, LPDWORD) = GetComputerNameW;
static BOOL (WINAPI *Real_GetComputerNameA)(LPSTR, LPDWORD) = GetComputerNameA;
static BOOL (WINAPI *Real_GetUserNameW)(LPWSTR, LPDWORD) = GetUserNameW;
static BOOL (WINAPI *Real_GetUserNameA)(LPSTR, LPDWORD) = GetUserNameA;

static DWORD (WINAPI *Real_GetCurrentProcessId)() = GetCurrentProcessId;
static DWORD (WINAPI *Real_GetProcessId)(HANDLE) = GetProcessId;
static BOOL (WINAPI *Real_GetProcessTimes)(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME) = GetProcessTimes;
static DWORD (WINAPI *Real_GetProcessHandleCount)(HANDLE) = GetProcessHandleCount;
static BOOL (WINAPI *Real_EnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD) = EnumProcessModules;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_RtlGetVersion)(PRTL_OSVERSIONINFOW);

static PFN_NtQuerySystemInformation Real_NtQuerySystemInformation_2 = nullptr;
static PFN_RtlGetVersion Real_RtlGetVersion = nullptr;

static BOOL (WINAPI *Real_OpenProcessToken)(HANDLE, DWORD, PHANDLE) = OpenProcessToken;
static BOOL (WINAPI *Real_AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD) = AdjustTokenPrivileges;
static BOOL (WINAPI *Real_LookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID) = LookupPrivilegeValueW;
static BOOL (WINAPI *Real_DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE) = DuplicateTokenEx;
static BOOL (WINAPI *Real_ImpersonateLoggedOnUser)(HANDLE) = ImpersonateLoggedOnUser;
static BOOL (WINAPI *Real_RevertToSelf)() = RevertToSelf;

static SC_HANDLE (WINAPI *Real_OpenSCManagerW)(LPCWSTR, LPCWSTR, DWORD) = OpenSCManagerW;
static SC_HANDLE (WINAPI *Real_OpenSCManagerA)(LPCSTR, LPCSTR, DWORD) = OpenSCManagerA;
static SC_HANDLE (WINAPI *Real_CreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR) = CreateServiceW;
static BOOL (WINAPI *Real_StartServiceW)(SC_HANDLE, DWORD, LPCWSTR*) = StartServiceW;
static BOOL (WINAPI *Real_ControlService)(SC_HANDLE, DWORD, LPSERVICE_STATUS) = ControlService;
static BOOL (WINAPI *Real_DeleteService)(SC_HANDLE) = DeleteService;

// ========== 辅助函数 ==========
static std::string GetPrivilegeName(LPCWSTR name) {
    if (!name) return "NULL";
    std::wstring w(name);
    std::string s(w.begin(), w.end());
    // 常见特权
    if (s == "SeDebugPrivilege") return "SeDebugPrivilege [DANGEROUS!]";
    if (s == "SeImpersonatePrivilege") return "SeImpersonatePrivilege";
    if (s == "SeTakeOwnershipPrivilege") return "SeTakeOwnershipPrivilege";
    if (s == "SeLoadDriverPrivilege") return "SeLoadDriverPrivilege";
    if (s == "SeRestorePrivilege") return "SeRestorePrivilege";
    if (s == "SeBackupPrivilege") return "SeBackupPrivilege";
    if (s == "SeTcbPrivilege") return "SeTcbPrivilege [DANGEROUS!]";
    if (s == "SeCreateTokenPrivilege") return "SeCreateTokenPrivilege [DANGEROUS!]";
    if (s == "SeAssignPrimaryTokenPrivilege") return "SeAssignPrimaryTokenPrivilege [DANGEROUS!]";
    return s;
}

static std::string GetServiceStartType(DWORD type) {
    switch (type) {
        case SERVICE_BOOT_START:   return "BOOT";
        case SERVICE_SYSTEM_START: return "SYSTEM";
        case SERVICE_AUTO_START:   return "AUTO";
        case SERVICE_DEMAND_START: return "DEMAND";
        case SERVICE_DISABLED:     return "DISABLED";
        default: return "TYPE_" + std::to_string(type);
    }
}

// ========== Hook 实现 ==========

void WINAPI Hook_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
    Real_GetSystemInfo(lpSystemInfo);

    if (lpSystemInfo) {
        std::ostringstream params;
        params << "Processors=" << lpSystemInfo->dwNumberOfProcessors
               << ", PageSize=" << lpSystemInfo->dwPageSize
               << ", ProcessorArch=" << lpSystemInfo->wProcessorArchitecture;

        LOG_API_CALL("kernel32.dll", "GetSystemInfo", params.str(), "VOID", ApiCategory::PRIVILEGE_SYSTEM);
    }
}

BOOL WINAPI Hook_GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize) {
    BOOL result = Real_GetComputerNameW(lpBuffer, nSize);

    if (result && lpBuffer) {
        std::ostringstream ret;
        ret << FmtBOOL(result) << " Name=" << FmtStrW(lpBuffer);
        LOG_API_CALL("kernel32.dll", "GetComputerNameW", "", ret.str(), ApiCategory::PRIVILEGE_SYSTEM);
    }

    return result;
}

BOOL WINAPI Hook_GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer) {
    BOOL result = Real_GetUserNameW(lpBuffer, pcbBuffer);

    if (result && lpBuffer) {
        std::ostringstream ret;
        ret << FmtBOOL(result) << " User=" << FmtStrW(lpBuffer);
        LOG_API_CALL("advapi32.dll", "GetUserNameW", "", ret.str(), ApiCategory::PRIVILEGE_SYSTEM);
    }

    return result;
}

BOOL WINAPI Hook_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
    std::ostringstream params;
    params << "hProcess=" << FmtHandle(ProcessHandle) << ", Access=" << FmtDWORD(DesiredAccess);

    // 检测敏感权限请求
    if (DesiredAccess & TOKEN_ADJUST_PRIVILEGES) params << " [ADJUST_PRIVILEGES]";
    if (DesiredAccess & TOKEN_DUPLICATE) params << " [DUPLICATE]";
    if (DesiredAccess & TOKEN_IMPERSONATE) params << " [IMPERSONATE]";

    BOOL result = Real_OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && TokenHandle) ret << " (Token=" << FmtHandle(*TokenHandle) << ")";

    LOG_API_CALL("advapi32.dll", "OpenProcessToken", params.str(), ret.str(), ApiCategory::PRIVILEGE_SYSTEM);
    return result;
}

BOOL WINAPI Hook_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    std::ostringstream params;
    params << "Token=" << FmtHandle(TokenHandle) << ", DisableAll=" << FmtBOOL(DisableAllPrivileges);

    if (NewState && NewState->PrivilegeCount > 0) {
        params << ", Privileges=[";
        for (DWORD i = 0; i < NewState->PrivilegeCount; i++) {
            if (i > 0) params << ", ";
            params << GetPrivilegeName(nullptr); // 这里需要LUID转名称
            params << "(LUID=" << NewState->Privileges[i].Luid.LowPart << ")";
            if (NewState->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) params << " [ENABLED]";
        }
        params << "]";
    }

    BOOL result = Real_AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("advapi32.dll", "AdjustTokenPrivileges", params.str(), ret.str(), ApiCategory::PRIVILEGE_SYSTEM);
    return result;
}

BOOL WINAPI Hook_ImpersonateLoggedOnUser(HANDLE hToken) {
    std::string params = "Token=" + FmtHandle(hToken);
    BOOL result = Real_ImpersonateLoggedOnUser(hToken);

    std::ostringstream ret;
    ret << FmtBOOL(result) << " [IMPERSONATION!]";

    LOG_API_CALL("advapi32.dll", "ImpersonateLoggedOnUser", params, ret.str(), ApiCategory::PRIVILEGE_SYSTEM);
    return result;
}

SC_HANDLE WINAPI Hook_OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess) {
    std::ostringstream params;
    params << "Machine=" << FmtStrW(lpMachineName) << ", Access=" << FmtDWORD(dwDesiredAccess);

    if (lpMachineName && wcslen(lpMachineName) > 0) {
        params << " [REMOTE!]";
    }
    if (dwDesiredAccess & SC_MANAGER_CREATE_SERVICE) params << " [CREATE_SERVICE]";

    SC_HANDLE result = Real_OpenSCManagerW(lpMachineName, lpDatabaseName, dwDesiredAccess);

    std::ostringstream ret;
    ret << FmtHandle(result);
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("advapi32.dll", "OpenSCManagerW", params.str(), ret.str(), ApiCategory::PRIVILEGE_SYSTEM);
    return result;
}

SC_HANDLE WINAPI Hook_CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName,
    DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl,
    LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId,
    LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword) {

    std::ostringstream params;
    params << "Name=" << FmtStrW(lpServiceName)
           << ", DisplayName=" << FmtStrW(lpDisplayName)
           << ", Binary=" << FmtStrW(lpBinaryPathName)
           << ", StartType=" << GetServiceStartType(dwStartType);

    SC_HANDLE result = Real_CreateServiceW(hSCManager, lpServiceName, lpDisplayName,
        dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl,
        lpBinaryPathName, lpLoadOrderGroup, lpdwTagId,
        lpDependencies, lpServiceStartName, lpPassword);

    std::ostringstream ret;
    ret << FmtHandle(result);
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("advapi32.dll", "CreateServiceW", params.str(), ret.str(), ApiCategory::PRIVILEGE_SYSTEM);
    return result;
}

BOOL WINAPI Hook_StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors) {
    std::ostringstream params;
    params << "hService=" << FmtHandle(hService) << ", NumArgs=" << dwNumServiceArgs;
    if (lpServiceArgVectors && dwNumServiceArgs > 0) {
        params << ", Args=[";
        for (DWORD i = 0; i < dwNumServiceArgs; i++) {
            if (i > 0) params << ", ";
            params << FmtStrW(lpServiceArgVectors[i]);
        }
        params << "]";
    }

    BOOL result = Real_StartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("advapi32.dll", "StartServiceW", params.str(), ret.str(), ApiCategory::PRIVILEGE_SYSTEM);
    return result;
}

void InstallSystemInfoHooks() {
    // 系统信息
    HOOK_API("GetSystemInfo", Hook_GetSystemInfo, Real_GetSystemInfo);
    HOOK_API("GetNativeSystemInfo", Hook_GetNativeSystemInfo, Real_GetNativeSystemInfo);
    HOOK_API("GetSystemTime", Hook_GetSystemTime, Real_GetSystemTime);
    HOOK_API("GetLocalTime", Hook_GetLocalTime, Real_GetLocalTime);
    HOOK_API("GetVersion", Hook_GetVersion, Real_GetVersion);
    HOOK_API("GetVersionExW", Hook_GetVersionExW, Real_GetVersionExW);
    HOOK_API("GetVersionExA", Hook_GetVersionExA, Real_GetVersionExA);

    // 计算机信息
    HOOK_API("GetComputerNameW", Hook_GetComputerNameW, Real_GetComputerNameW);
    HOOK_API("GetComputerNameA", Hook_GetComputerNameA, Real_GetComputerNameA);
    HOOK_API("GetComputerNameExW", Hook_GetComputerNameExW, Real_GetComputerNameExW);
    HOOK_API_ADVAPI32("GetUserNameW", Hook_GetUserNameW, Real_GetUserNameW);
    HOOK_API_ADVAPI32("GetUserNameA", Hook_GetUserNameA, Real_GetUserNameA);

    // 进程信息
    HOOK_API("GetCurrentProcessId", Hook_GetCurrentProcessId, Real_GetCurrentProcessId);
    HOOK_API("GetProcessId", Hook_GetProcessId, Real_GetProcessId);
    HOOK_API("GetProcessTimes", Hook_GetProcessTimes, Real_GetProcessTimes);
    HOOK_API("GetProcessHandleCount", Hook_GetProcessHandleCount, Real_GetProcessHandleCount);
    HOOK_API_FULL("psapi.dll", "GetProcessImageFileNameW", Hook_GetProcessImageFileNameW, Real_GetProcessImageFileNameW);
    HOOK_API_FULL("psapi.dll", "EnumProcessModules", Hook_EnumProcessModules, Real_EnumProcessModules);

    // 权限相关
    HOOK_API_ADVAPI32("OpenProcessToken", Hook_OpenProcessToken, Real_OpenProcessToken);
    HOOK_API_ADVAPI32("AdjustTokenPrivileges", Hook_AdjustTokenPrivileges, Real_AdjustTokenPrivileges);
    HOOK_API_ADVAPI32("LookupPrivilegeValueW", Hook_LookupPrivilegeValueW, Real_LookupPrivilegeValueW);
    HOOK_API_ADVAPI32("DuplicateTokenEx", Hook_DuplicateTokenEx, Real_DuplicateTokenEx);
    HOOK_API_ADVAPI32("ImpersonateLoggedOnUser", Hook_ImpersonateLoggedOnUser, Real_ImpersonateLoggedOnUser);
    HOOK_API_ADVAPI32("RevertToSelf", Hook_RevertToSelf, Real_RevertToSelf);

    // 服务管理
    HOOK_API_ADVAPI32("OpenSCManagerW", Hook_OpenSCManagerW, Real_OpenSCManagerW);
    HOOK_API_ADVAPI32("OpenSCManagerA", Hook_OpenSCManagerA, Real_OpenSCManagerA);
    HOOK_API_ADVAPI32("CreateServiceW", Hook_CreateServiceW, Real_CreateServiceW);
    HOOK_API_ADVAPI32("StartServiceW", Hook_StartServiceW, Real_StartServiceW);
    HOOK_API_ADVAPI32("ControlService", Hook_ControlService, Real_ControlService);
    HOOK_API_ADVAPI32("DeleteService", Hook_DeleteService, Real_DeleteService);

    // NTDLL
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        Real_NtQuerySystemInformation_2 = (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (Real_NtQuerySystemInformation_2) {
            MH_CreateHook(Real_NtQuerySystemInformation_2, Hook_NtQuerySystemInformation, (LPVOID*)&Real_NtQuerySystemInformation_2);
            MH_EnableHook(Real_NtQuerySystemInformation_2);
        }

        Real_RtlGetVersion = (PFN_RtlGetVersion)GetProcAddress(hNtdll, "RtlGetVersion");
        if (Real_RtlGetVersion) {
            MH_CreateHook(Real_RtlGetVersion, Hook_RtlGetVersion, (LPVOID*)&Real_RtlGetVersion);
            MH_EnableHook(Real_RtlGetVersion);
        }
    }
}