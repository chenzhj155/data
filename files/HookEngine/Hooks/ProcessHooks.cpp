#include "ProcessHooks.h"
#include "../HookEngine.h"
#include <sstream>

static BOOL (WINAPI *Real_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
static BOOL (WINAPI *Real_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
static HANDLE (WINAPI *Real_OpenProcess)(DWORD, BOOL, DWORD) = OpenProcess;
static BOOL (WINAPI *Real_TerminateProcess)(HANDLE, UINT) = TerminateProcess;
static void (WINAPI *Real_ExitProcess)(UINT) = ExitProcess;
static DWORD (WINAPI *Real_GetProcessId)(HANDLE) = GetProcessId;
static BOOL (WINAPI *Real_GetExitCodeProcess)(HANDLE, LPDWORD) = GetExitCodeProcess;
static BOOL (WINAPI *Real_SetProcessDEPPolicy)(DWORD) = SetProcessDEPPolicy;

static std::string GetCreationFlags(DWORD flags) {
    std::vector<std::string> f;
    if (flags & CREATE_SUSPENDED)        f.push_back("SUSPENDED");
    if (flags & CREATE_NEW_CONSOLE)      f.push_back("NEW_CONSOLE");
    if (flags & CREATE_NEW_PROCESS_GROUP)f.push_back("NEW_PROCESS_GROUP");
    if (flags & CREATE_NO_WINDOW)        f.push_back("NO_WINDOW");
    if (flags & DETACHED_PROCESS)        f.push_back("DETACHED");
    if (flags & DEBUG_PROCESS)           f.push_back("DEBUG_PROCESS");
    if (flags & DEBUG_ONLY_THIS_PROCESS) f.push_back("DEBUG_ONLY_THIS");
    if (flags & CREATE_DEFAULT_ERROR_MODE) f.push_back("DEFAULT_ERROR_MODE");

    std::string result;
    for (size_t i = 0; i < f.size(); i++) {
        if (i > 0) result += "|";
        result += f[i];
    }
    return result.empty() ? "0" : result;
}

BOOL WINAPI Hook_CreateProcessW(LPCWSTR lpApp, LPWSTR lpCmd, LPSECURITY_ATTRIBUTES lpPA,
    LPSECURITY_ATTRIBUTES lpTA, BOOL bInherit, DWORD dwFlags, LPVOID lpEnv,
    LPCWSTR lpDir, LPSTARTUPINFOW lpSI, LPPROCESS_INFORMATION lpPI) {

    std::ostringstream params;
    if (lpApp) params << "App=" << FmtStrW(lpApp);
    if (lpCmd) params << " Cmd=" << FmtStrW(lpCmd);
    params << " Flags=" << GetCreationFlags(dwFlags);

    BOOL result = Real_CreateProcessW(lpApp, lpCmd, lpPA, lpTA, bInherit, dwFlags, lpEnv, lpDir, lpSI, lpPI);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpPI) ret << " (PID:" << lpPI->dwProcessId << " TID:" << lpPI->dwThreadId << ")";
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("kernel32.dll", "CreateProcessW", params.str(), ret.str(), ApiCategory::PROCESS_CREATION);
    return result;
}

BOOL WINAPI Hook_CreateProcessA(LPCSTR lpApp, LPSTR lpCmd, LPSECURITY_ATTRIBUTES lpPA,
    LPSECURITY_ATTRIBUTES lpTA, BOOL bInherit, DWORD dwFlags, LPVOID lpEnv,
    LPCSTR lpDir, LPSTARTUPINFOA lpSI, LPPROCESS_INFORMATION lpPI) {

    std::ostringstream params;
    if (lpApp) params << "App=" << FmtStrA(lpApp);
    if (lpCmd) params << " Cmd=" << FmtStrA(lpCmd);
    params << " Flags=" << GetCreationFlags(dwFlags);

    BOOL result = Real_CreateProcessA(lpApp, lpCmd, lpPA, lpTA, bInherit, dwFlags, lpEnv, lpDir, lpSI, lpPI);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpPI) ret << " (PID:" << lpPI->dwProcessId << " TID:" << lpPI->dwThreadId << ")";
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("kernel32.dll", "CreateProcessA", params.str(), ret.str(), ApiCategory::PROCESS_CREATION);
    return result;
}

HANDLE WINAPI Hook_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    std::ostringstream params;
    params << "PID=" << dwProcessId << ", Access=" << FmtDWORD(dwDesiredAccess);

    // 检测可疑权限
    std::vector<std::string> rights;
    if (dwDesiredAccess & PROCESS_VM_OPERATION)    rights.push_back("VM_OP");
    if (dwDesiredAccess & PROCESS_VM_WRITE)        rights.push_back("VM_WRITE");
    if (dwDesiredAccess & PROCESS_VM_READ)         rights.push_back("VM_READ");
    if (dwDesiredAccess & PROCESS_CREATE_THREAD)   rights.push_back("CREATE_THREAD");
    if (dwDesiredAccess & PROCESS_DUP_HANDLE)      rights.push_back("DUP_HANDLE");
    if (dwDesiredAccess & PROCESS_SET_INFORMATION) rights.push_back("SET_INFO");
    if (dwDesiredAccess & PROCESS_QUERY_INFORMATION) rights.push_back("QUERY_INFO");
    if (dwDesiredAccess & PROCESS_SUSPEND_RESUME)  rights.push_back("SUSPEND_RESUME");
    if (dwDesiredAccess & PROCESS_TERMINATE)       rights.push_back("TERMINATE");

    if (!rights.empty()) {
        params << " [";
        for (size_t i = 0; i < rights.size(); i++) {
            if (i > 0) params << "|";
            params << rights[i];
        }
        params << "]";
    }

    HANDLE result = Real_OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

    std::ostringstream ret;
    ret << FmtHandle(result);
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("kernel32.dll", "OpenProcess", params.str(), ret.str(), ApiCategory::PROCESS_CREATION);
    return result;
}

BOOL WINAPI Hook_TerminateProcess(HANDLE hProcess, UINT uExitCode) {
    std::ostringstream params;
    params << "hProcess=" << FmtHandle(hProcess) << ", ExitCode=" << uExitCode;

    BOOL result = Real_TerminateProcess(hProcess, uExitCode);

    LOG_API_CALL("kernel32.dll", "TerminateProcess", params.str(), FmtBOOL(result), ApiCategory::PROCESS_CREATION);
    return result;
}

void WINAPI Hook_ExitProcess(UINT uExitCode) {
    std::string params = "ExitCode=" + std::to_string(uExitCode);
    // 在退出前记录
    LOG_API_CALL("kernel32.dll", "ExitProcess", params, "VOID", ApiCategory::PROCESS_CREATION);
    // 确保日志写入
    ApiDatabase::GetInstance().Shutdown();
    Real_ExitProcess(uExitCode);
}

void InstallProcessHooks() {
    HOOK_API("CreateProcessW", Hook_CreateProcessW, Real_CreateProcessW);
    HOOK_API("CreateProcessA", Hook_CreateProcessA, Real_CreateProcessA);
    HOOK_API("OpenProcess", Hook_OpenProcess, Real_OpenProcess);
    HOOK_API("TerminateProcess", Hook_TerminateProcess, Real_TerminateProcess);
    HOOK_API("GetProcessId", Hook_GetProcessId, Real_GetProcessId);
    HOOK_API("GetExitCodeProcess", Hook_GetExitCodeProcess, Real_GetExitCodeProcess);
    HOOK_API("SetProcessDEPPolicy", Hook_SetProcessDEPPolicy, Real_SetProcessDEPPolicy);
}