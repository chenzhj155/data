#include "AntiDebugHooks.h"
#include "../HookEngine.h"
#include <sstream>
#include <iomanip>

// ========== 原始函数指针 ==========
static BOOL (WINAPI *Real_IsDebuggerPresent)() = IsDebuggerPresent;
static BOOL (WINAPI *Real_CheckRemoteDebuggerPresent)(HANDLE, PBOOL) = CheckRemoteDebuggerPresent;
static BOOL (WINAPI *Real_DebugActiveProcess)(DWORD) = DebugActiveProcess;
static BOOL (WINAPI *Real_DebugActiveProcessStop)(DWORD) = DebugActiveProcessStop;
static void (WINAPI *Real_DebugBreak)() = DebugBreak;
static void (WINAPI *Real_OutputDebugStringA)(LPCSTR) = OutputDebugStringA;
static void (WINAPI *Real_OutputDebugStringW)(LPCWSTR) = OutputDebugStringW;

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtSetInformationThread)(HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtClose)(HANDLE);
typedef NTSTATUS (NTAPI *PFN_NtQueryPerformanceCounter)(PLARGE_INTEGER, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *PFN_NtRaiseException)(PEXCEPTION_RECORD, PCONTEXT, BOOL);

static PFN_NtQueryInformationProcess Real_NtQueryInformationProcess = nullptr;
static PFN_NtSetInformationThread Real_NtSetInformationThread = nullptr;
static PFN_NtQuerySystemInformation Real_NtQuerySystemInformation = nullptr;
static PFN_NtClose Real_NtClose = nullptr;
static PFN_NtQueryPerformanceCounter Real_NtQueryPerformanceCounter = nullptr;
static PFN_NtRaiseException Real_NtRaiseException = nullptr;

static DWORD (WINAPI *Real_GetTickCount)() = GetTickCount;
static ULONGLONG (WINAPI *Real_GetTickCount64)() = GetTickCount64;
static BOOL (WINAPI *Real_QueryPerformanceCounter)(LARGE_INTEGER*) = QueryPerformanceCounter;
static LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *Real_SetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER) = SetUnhandledExceptionFilter;
static void (WINAPI *Real_RaiseException)(DWORD, DWORD, DWORD, const ULONG_PTR*) = RaiseException;
static HANDLE (WINAPI *Real_CreateToolhelp32Snapshot)(DWORD, DWORD) = CreateToolhelp32Snapshot;

// ========== 辅助函数 ==========
static std::string GetProcessInfoClassName(DWORD cls) {
    switch (cls) {
        case 0:  return "ProcessBasicInformation";
        case 7:  return "ProcessDebugPort [DEBUG CHECK!]";
        case 8:  return "ProcessWow64Information";
        case 9:  return "ProcessImageFileName";
        case 29: return "ProcessBreakOnTermination";
        case 30: return "ProcessDebugObjectHandle [DEBUG CHECK!]";
        case 31: return "ProcessDebugFlags [DEBUG CHECK!]";
        default: return "Class_" + std::to_string(cls);
    }
}

static std::string GetThreadInfoClassName(DWORD cls) {
    switch (cls) {
        case 0x11: return "ThreadHideFromDebugger [HIDE THREAD!]";
        case 0x12: return "ThreadBreakOnTermination";
        default:   return "Class_0x" + FmtDWORD(cls).substr(2);
    }
}

static std::string GetSystemInfoClassName(DWORD cls) {
    switch (cls) {
        case 0x05: return "SystemProcessInformation [ENUM PROCESSES]";
        case 0x23: return "SystemKernelDebuggerInformation [DEBUG CHECK!]";
        default:   return "Class_" + std::to_string(cls);
    }
}

// ========== Hook 实现 ==========

BOOL WINAPI Hook_IsDebuggerPresent() {
    BOOL result = Real_IsDebuggerPresent();

    std::ostringstream params;
    params << "Result=" << FmtBOOL(result);
    if (result) params << " [DEBUGGER DETECTED!]";

    LOG_API_CALL("kernel32.dll", "IsDebuggerPresent", "", params.str(), ApiCategory::ANTI_DEBUG);
    return result;
}

BOOL WINAPI Hook_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    BOOL result = Real_CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && pbDebuggerPresent) {
        ret << " (DebuggerPresent=" << FmtBOOL(*pbDebuggerPresent) << ")";
        if (*pbDebuggerPresent) ret << " [REMOTE DEBUGGER FOUND!]";
    }

    std::string params = "hProcess=" + FmtHandle(hProcess);
    LOG_API_CALL("kernel32.dll", "CheckRemoteDebuggerPresent", params, ret.str(), ApiCategory::ANTI_DEBUG);
    return result;
}

NTSTATUS NTAPI Hook_NtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    std::ostringstream params;
    params << "hProcess=" << FmtHandle(ProcessHandle)
           << ", InfoClass=" << GetProcessInfoClassName(ProcessInformationClass);

    NTSTATUS result = Real_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;

    // 特别关注反调试相关的查询
    if (ProcessInformationClass == 7 || ProcessInformationClass == 30 || ProcessInformationClass == 31) {
        if (result == 0 && ProcessInformation) {
            if (ProcessInformationClass == 7) {
                DWORD64 debugPort = *(DWORD64*)ProcessInformation;
                ret << " DebugPort=" << debugPort;
                if (debugPort != 0) ret << " [DEBUGGER DETECTED!]";
            } else if (ProcessInformationClass == 31) {
                BOOL noDebugInherit = *(BOOL*)ProcessInformation;
                ret << " NoDebugInherit=" << FmtBOOL(noDebugInherit);
            }
        }
    }

    LOG_API_CALL("ntdll.dll", "NtQueryInformationProcess", params.str(), ret.str(), ApiCategory::ANTI_DEBUG);
    return result;
}

NTSTATUS NTAPI Hook_NtSetInformationThread(HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {
    std::ostringstream params;
    params << "hThread=" << FmtHandle(ThreadHandle)
           << ", InfoClass=" << GetThreadInfoClassName(ThreadInformationClass);

    // ThreadHideFromDebugger 是常见的反调试技术
    if (ThreadInformationClass == 0x11) {
        params << " [ATTEMPTING TO HIDE FROM DEBUGGER!]";
    }

    NTSTATUS result = Real_NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;

    LOG_API_CALL("ntdll.dll", "NtSetInformationThread", params.str(), ret.str(), ApiCategory::ANTI_DEBUG);
    return result;
}

NTSTATUS NTAPI Hook_NtClose(HANDLE Handle) {
    // 检测是否在关闭调试对象句柄
    std::ostringstream params;
    params << "Handle=" << FmtHandle(Handle);

    // 可以通过查询对象类型来判断是否在关闭调试相关句柄
    // 但这里简单记录所有 NtClose 调用以避免性能问题

    NTSTATUS result = Real_NtClose(Handle);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;

    // 只在高可疑时记录详细日志
    // LOG_API_CALL("ntdll.dll", "NtClose", params.str(), ret.str(), ApiCategory::ANTI_DEBUG);
    return result;
}

void WINAPI Hook_OutputDebugStringA(LPCSTR lpOutputString) {
    // 程序可能通过 OutputDebugString 发送反调试信息
    if (lpOutputString && strlen(lpOutputString) > 0) {
        LOG_API_CALL("kernel32.dll", "OutputDebugStringA", FmtStrA(lpOutputString), "VOID", ApiCategory::ANTI_DEBUG);
    }
    Real_OutputDebugStringA(lpOutputString);
}

DWORD WINAPI Hook_GetTickCount() {
    DWORD result = Real_GetTickCount();
    // 频繁调用 GetTickCount 可能是反沙箱/反调试的时间检测
    // 这里不记录每次调用以避免日志过多，但保留 Hook 点以便过滤
    return result;
}

void WINAPI Hook_RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments) {
    std::ostringstream params;
    params << "Code=0x" << std::hex << dwExceptionCode
           << ", Flags=0x" << dwExceptionFlags
           << ", Args=" << nNumberOfArguments;

    // 某些异常代码用于反调试
    if (dwExceptionCode == 0x40010006) params << " [DBG_PRINTEXCEPTION_C]";
    if (dwExceptionCode == 0x4001000A) params << " [DBG_RIPEXCEPTION - AntiDebug!]";

    // 先记录再调用原始函数
    LOG_API_CALL("kernel32.dll", "RaiseException", params.str(), "VOID", ApiCategory::ANTI_DEBUG);

    Real_RaiseException(dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments);
}

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hook_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
    std::ostringstream params;
    params << "Filter=0x" << std::hex << (DWORD64)lpTopLevelExceptionFilter;

    LPTOP_LEVEL_EXCEPTION_FILTER result = Real_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);

    std::ostringstream ret;
    ret << "OldFilter=0x" << std::hex << (DWORD64)result;

    LOG_API_CALL("kernel32.dll", "SetUnhandledExceptionFilter", params.str(), ret.str(), ApiCategory::ANTI_DEBUG);
    return result;
}

void InstallAntiDebugHooks() {
    HOOK_API("IsDebuggerPresent", Hook_IsDebuggerPresent, Real_IsDebuggerPresent);
    HOOK_API("CheckRemoteDebuggerPresent", Hook_CheckRemoteDebuggerPresent, Real_CheckRemoteDebuggerPresent);
    HOOK_API("DebugActiveProcess", Hook_DebugActiveProcess, Real_DebugActiveProcess);
    HOOK_API("DebugActiveProcessStop", Hook_DebugActiveProcessStop, Real_DebugActiveProcessStop);
    HOOK_API("DebugBreak", Hook_DebugBreak, Real_DebugBreak);
    HOOK_API("OutputDebugStringA", Hook_OutputDebugStringA, Real_OutputDebugStringA);
    HOOK_API("OutputDebugStringW", Hook_OutputDebugStringW, Real_OutputDebugStringW);
    HOOK_API("GetTickCount", Hook_GetTickCount, Real_GetTickCount);
    HOOK_API("GetTickCount64", Hook_GetTickCount64, Real_GetTickCount64);
    HOOK_API("QueryPerformanceCounter", Hook_QueryPerformanceCounter, Real_QueryPerformanceCounter);
    HOOK_API("SetUnhandledExceptionFilter", Hook_SetUnhandledExceptionFilter, Real_SetUnhandledExceptionFilter);
    HOOK_API("RaiseException", Hook_RaiseException, Real_RaiseException);
    HOOK_API("CreateToolhelp32Snapshot", Hook_CreateToolhelp32Snapshot, Real_CreateToolhelp32Snapshot);

    // NTDLL函数
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        Real_NtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (Real_NtQueryInformationProcess) {
            MH_CreateHook(Real_NtQueryInformationProcess, Hook_NtQueryInformationProcess, (LPVOID*)&Real_NtQueryInformationProcess);
            MH_EnableHook(Real_NtQueryInformationProcess);
        }

        Real_NtSetInformationThread = (PFN_NtSetInformationThread)GetProcAddress(hNtdll, "NtSetInformationThread");
        if (Real_NtSetInformationThread) {
            MH_CreateHook(Real_NtSetInformationThread, Hook_NtSetInformationThread, (LPVOID*)&Real_NtSetInformationThread);
            MH_EnableHook(Real_NtSetInformationThread);
        }

        Real_NtQuerySystemInformation = (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
        if (Real_NtQuerySystemInformation) {
            MH_CreateHook(Real_NtQuerySystemInformation, Hook_NtQuerySystemInformation, (LPVOID*)&Real_NtQuerySystemInformation);
            MH_EnableHook(Real_NtQuerySystemInformation);
        }

        Real_NtClose = (PFN_NtClose)GetProcAddress(hNtdll, "NtClose");
        if (Real_NtClose) {
            MH_CreateHook(Real_NtClose, Hook_NtClose, (LPVOID*)&Real_NtClose);
            MH_EnableHook(Real_NtClose);
        }

        Real_NtQueryPerformanceCounter = (PFN_NtQueryPerformanceCounter)GetProcAddress(hNtdll, "NtQueryPerformanceCounter");
        if (Real_NtQueryPerformanceCounter) {
            MH_CreateHook(Real_NtQueryPerformanceCounter, Hook_NtQueryPerformanceCounter, (LPVOID*)&Real_NtQueryPerformanceCounter);
            MH_EnableHook(Real_NtQueryPerformanceCounter);
        }

        Real_NtRaiseException = (PFN_NtRaiseException)GetProcAddress(hNtdll, "NtRaiseException");
        if (Real_NtRaiseException) {
            MH_CreateHook(Real_NtRaiseException, Hook_NtRaiseException, (LPVOID*)&Real_NtRaiseException);
            MH_EnableHook(Real_NtRaiseException);
        }
    }
}