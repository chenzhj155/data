#include "SyncHooks.h"
#include "../HookEngine.h"
#include <sstream>

static HANDLE (WINAPI *Real_CreateMutexW)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR) = CreateMutexW;
static HANDLE (WINAPI *Real_CreateMutexA)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR) = CreateMutexA;
static HANDLE (WINAPI *Real_OpenMutexW)(DWORD, BOOL, LPCWSTR) = OpenMutexW;
static BOOL (WINAPI *Real_ReleaseMutex)(HANDLE) = ReleaseMutex;
static HANDLE (WINAPI *Real_CreateEventW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR) = CreateEventW;
static BOOL (WINAPI *Real_SetEvent)(HANDLE) = SetEvent;
static BOOL (WINAPI *Real_ResetEvent)(HANDLE) = ResetEvent;
static DWORD (WINAPI *Real_WaitForSingleObject)(HANDLE, DWORD) = WaitForSingleObject;
static DWORD (WINAPI *Real_WaitForMultipleObjects)(DWORD, const HANDLE*, BOOL, DWORD) = WaitForMultipleObjects;

HANDLE WINAPI Hook_CreateMutexW(LPSECURITY_ATTRIBUTES lpMA, BOOL bInitialOwner, LPCWSTR lpName) {
    std::ostringstream params;
    params << "Name=" << FmtStrW(lpName) << ", InitialOwner=" << FmtBOOL(bInitialOwner);
    HANDLE result = Real_CreateMutexW(lpMA, bInitialOwner, lpName);
    LOG_API_CALL("kernel32.dll", "CreateMutexW", params.str(), FmtHandle(result), ApiCategory::SYNCHRONIZATION);
    return result;
}

HANDLE WINAPI Hook_CreateEventW(LPSECURITY_ATTRIBUTES lpEA, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName) {
    std::ostringstream params;
    params << "Name=" << FmtStrW(lpName) << ", ManualReset=" << FmtBOOL(bManualReset)
           << ", InitialState=" << FmtBOOL(bInitialState);
    HANDLE result = Real_CreateEventW(lpEA, bManualReset, bInitialState, lpName);
    LOG_API_CALL("kernel32.dll", "CreateEventW", params.str(), FmtHandle(result), ApiCategory::SYNCHRONIZATION);
    return result;
}

DWORD WINAPI Hook_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    std::ostringstream params;
    params << "Handle=" << FmtHandle(hHandle) << ", Timeout=";
    if (dwMilliseconds == INFINITE) params << "INFINITE";
    else params << dwMilliseconds << "ms";

    DWORD result = Real_WaitForSingleObject(hHandle, dwMilliseconds);

    std::string ret;
    switch (result) {
        case WAIT_OBJECT_0: ret = "WAIT_OBJECT_0"; break;
        case WAIT_TIMEOUT:  ret = "WAIT_TIMEOUT";  break;
        case WAIT_ABANDONED:ret = "WAIT_ABANDONED";break;
        case WAIT_FAILED:   ret = "WAIT_FAILED";   break;
        default:            ret = std::to_string(result); break;
    }

    LOG_API_CALL("kernel32.dll", "WaitForSingleObject", params.str(), ret, ApiCategory::SYNCHRONIZATION);
    return result;
}

void InstallSyncHooks() {
    HOOK_API("CreateMutexW", Hook_CreateMutexW, Real_CreateMutexW);
    HOOK_API("CreateEventW", Hook_CreateEventW, Real_CreateEventW);
    HOOK_API("SetEvent", Hook_SetEvent, Real_SetEvent);
    HOOK_API("ResetEvent", Hook_ResetEvent, Real_ResetEvent);
    HOOK_API("WaitForSingleObject", Hook_WaitForSingleObject, Real_WaitForSingleObject);
    HOOK_API("WaitForMultipleObjects", Hook_WaitForMultipleObjects, Real_WaitForMultipleObjects);
}