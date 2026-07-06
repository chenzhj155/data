#include "ThreadHooks.h"
#include "../HookEngine.h"
#include <sstream>

static HANDLE (WINAPI *Real_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateThread;
static HANDLE (WINAPI *Real_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
static HANDLE (WINAPI *Real_CreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) = CreateRemoteThreadEx;
static HANDLE (WINAPI *Real_OpenThread)(DWORD, BOOL, DWORD) = OpenThread;
static DWORD (WINAPI *Real_SuspendThread)(HANDLE) = SuspendThread;
static DWORD (WINAPI *Real_ResumeThread)(HANDLE) = ResumeThread;
static BOOL (WINAPI *Real_TerminateThread)(HANDLE, DWORD) = TerminateThread;
static BOOL (WINAPI *Real_GetThreadContext)(HANDLE, LPCONTEXT) = GetThreadContext;
static BOOL (WINAPI *Real_SetThreadContext)(HANDLE, const CONTEXT*) = SetThreadContext;
static DWORD (WINAPI *Real_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR) = QueueUserAPC;

HANDLE WINAPI Hook_CreateThread(LPSECURITY_ATTRIBUTES lpTA, SIZE_T dwStack, LPTHREAD_START_ROUTINE lpStart,
    LPVOID lpParam, DWORD dwFlags, LPDWORD lpThreadId) {

    std::ostringstream params;
    params << "StartAddr=" << FmtPtr((void*)lpStart) << ", Param=" << FmtPtr(lpParam)
           << ", StackSize=0x" << std::hex << dwStack
           << ", Flags=" << FmtDWORD(dwFlags);

    HANDLE result = Real_CreateThread(lpTA, dwStack, lpStart, lpParam, dwFlags, lpThreadId);

    std::ostringstream ret;
    ret << FmtHandle(result);
    if (result && lpThreadId) ret << " (TID:" << *lpThreadId << ")";

    LOG_API_CALL("kernel32.dll", "CreateThread", params.str(), ret.str(), ApiCategory::THREAD_OPERATION);
    return result;
}

HANDLE WINAPI Hook_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpTA, SIZE_T dwStack,
    LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam, DWORD dwFlags, LPDWORD lpThreadId) {

    std::ostringstream params;
    params << "hProcess=" << FmtHandle(hProcess) << ", StartAddr=" << FmtPtr((void*)lpStart)
           << ", Param=" << FmtPtr(lpParam);

    HANDLE result = Real_CreateRemoteThread(hProcess, lpTA, dwStack, lpStart, lpParam, dwFlags, lpThreadId);

    std::ostringstream ret;
    ret << FmtHandle(result);
    if (result && lpThreadId) ret << " (TID:" << *lpThreadId << ")";

    LOG_API_CALL("kernel32.dll", "CreateRemoteThread", params.str(), ret.str(), ApiCategory::THREAD_OPERATION);
    return result;
}

DWORD WINAPI Hook_QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData) {
    std::ostringstream params;
    params << "APC=" << FmtPtr((void*)pfnAPC) << ", hThread=" << FmtHandle(hThread) << ", Data=" << FmtPtr((void*)dwData);

    DWORD result = Real_QueueUserAPC(pfnAPC, hThread, dwData);

    std::ostringstream ret;
    ret << result;
    if (result == 0) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("kernel32.dll", "QueueUserAPC", params.str(), ret.str(), ApiCategory::THREAD_OPERATION);
    return result;
}

BOOL WINAPI Hook_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    std::string params = "hThread=" + FmtHandle(hThread);
    BOOL result = Real_GetThreadContext(hThread, lpContext);
    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result) ret << " (Context=0x" << std::hex << (DWORD64)lpContext << ")";
    LOG_API_CALL("kernel32.dll", "GetThreadContext", params, ret.str(), ApiCategory::THREAD_OPERATION);
    return result;
}

BOOL WINAPI Hook_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    std::ostringstream params;
    params << "hThread=" << FmtHandle(hThread) << ", Context=0x" << std::hex << (DWORD64)lpContext;
    if (lpContext) params << " (RIP=0x" << std::hex << lpContext->Rip << ")";

    BOOL result = Real_SetThreadContext(hThread, lpContext);

    LOG_API_CALL("kernel32.dll", "SetThreadContext", params.str(), FmtBOOL(result), ApiCategory::THREAD_OPERATION);
    return result;
}

void InstallThreadHooks() {
    HOOK_API("CreateThread", Hook_CreateThread, Real_CreateThread);
    HOOK_API("CreateRemoteThread", Hook_CreateRemoteThread, Real_CreateRemoteThread);
    HOOK_API("CreateRemoteThreadEx", Hook_CreateRemoteThreadEx, Real_CreateRemoteThreadEx);
    HOOK_API("OpenThread", Hook_OpenThread, Real_OpenThread);
    HOOK_API("SuspendThread", Hook_SuspendThread, Real_SuspendThread);
    HOOK_API("ResumeThread", Hook_ResumeThread, Real_ResumeThread);
    HOOK_API("TerminateThread", Hook_TerminateThread, Real_TerminateThread);
    HOOK_API("GetThreadContext", Hook_GetThreadContext, Real_GetThreadContext);
    HOOK_API("SetThreadContext", Hook_SetThreadContext, Real_SetThreadContext);
    HOOK_API("QueueUserAPC", Hook_QueueUserAPC, Real_QueueUserAPC);
}