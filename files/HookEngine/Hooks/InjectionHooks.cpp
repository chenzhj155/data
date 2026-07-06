#include "InjectionHooks.h"
#include "../HookEngine.h"
#include <sstream>
#include <iomanip>

// ========== 原始函数指针 ==========
static HMODULE (WINAPI *Real_LoadLibraryW)(LPCWSTR) = LoadLibraryW;
static HMODULE (WINAPI *Real_LoadLibraryA)(LPCSTR) = LoadLibraryA;
static HMODULE (WINAPI *Real_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD) = LoadLibraryExW;
static HMODULE (WINAPI *Real_LoadLibraryExA)(LPCSTR, HANDLE, DWORD) = LoadLibraryExA;
static FARPROC (WINAPI *Real_GetProcAddress)(HMODULE, LPCSTR) = GetProcAddress;
static HMODULE (WINAPI *Real_GetModuleHandleW)(LPCWSTR) = GetModuleHandleW;
static HMODULE (WINAPI *Real_GetModuleHandleA)(LPCSTR) = GetModuleHandleA;

static HHOOK (WINAPI *Real_SetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD) = SetWindowsHookExW;
static HHOOK (WINAPI *Real_SetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD) = SetWindowsHookExA;
static BOOL (WINAPI *Real_UnhookWindowsHookEx)(HHOOK) = UnhookWindowsHookEx;
static LRESULT (WINAPI *Real_CallNextHookEx)(HHOOK, int, WPARAM, LPARAM) = CallNextHookEx;

static HRESULT (WINAPI *Real_CoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*) = CoCreateInstance;
static HRESULT (WINAPI *Real_CoGetClassObject)(REFCLSID, DWORD, LPVOID, REFIID, LPVOID*) = CoGetClassObject;

static HANDLE (WINAPI *Real_CreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) = CreateRemoteThreadEx;

typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
static PFN_NtCreateThreadEx Real_NtCreateThreadEx = nullptr;

typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
static PFN_NtMapViewOfSection Real_NtMapViewOfSection = nullptr;

static HANDLE (WINAPI *Real_CreateFileMappingW_2)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR) = CreateFileMappingW;
static HANDLE (WINAPI *Real_OpenFileMappingW)(DWORD, BOOL, LPCWSTR) = OpenFileMappingW;

// ========== 辅助函数 ==========
static std::string GetHookTypeName(int idHook) {
    switch (idHook) {
        case WH_CALLWNDPROC:      return "WH_CALLWNDPROC";
        case WH_CALLWNDPROCRET:   return "WH_CALLWNDPROCRET";
        case WH_CBT:              return "WH_CBT";
        case WH_DEBUG:            return "WH_DEBUG";
        case WH_FOREGROUNDIDLE:   return "WH_FOREGROUNDIDLE";
        case WH_GETMESSAGE:       return "WH_GETMESSAGE";
        case WH_JOURNALPLAYBACK:  return "WH_JOURNALPLAYBACK";
        case WH_JOURNALRECORD:    return "WH_JOURNALRECORD";
        case WH_KEYBOARD:         return "WH_KEYBOARD";
        case WH_KEYBOARD_LL:      return "WH_KEYBOARD_LL";
        case WH_MOUSE:            return "WH_MOUSE";
        case WH_MOUSE_LL:         return "WH_MOUSE_LL";
        case WH_MSGFILTER:        return "WH_MSGFILTER";
        case WH_SHELL:            return "WH_SHELL";
        case WH_SYSMSGFILTER:     return "WH_SYSMSGFILTER";
        default:                  return "WH_" + std::to_string(idHook);
    }
}

// ========== Hook 实现 ==========

HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR lpLibFileName) {
    std::string params = "DLL=" + FmtStrW(lpLibFileName);

    HMODULE result = Real_LoadLibraryW(lpLibFileName);

    std::ostringstream ret;
    ret << FmtPtr(result);
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("kernel32.dll", "LoadLibraryW", params, ret.str(), ApiCategory::INJECTION);
    return result;
}

HMODULE WINAPI Hook_LoadLibraryA(LPCSTR lpLibFileName) {
    std::string params = "DLL=" + FmtStrA(lpLibFileName);

    HMODULE result = Real_LoadLibraryA(lpLibFileName);

    std::ostringstream ret;
    ret << FmtPtr(result);
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("kernel32.dll", "LoadLibraryA", params, ret.str(), ApiCategory::INJECTION);
    return result;
}

HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    std::ostringstream params;
    params << "DLL=" << FmtStrW(lpLibFileName) << ", Flags=" << FmtDWORD(dwFlags);
    if (dwFlags & DONT_RESOLVE_DLL_REFERENCES) params << " [DONT_RESOLVE]";
    if (dwFlags & LOAD_LIBRARY_AS_DATAFILE) params << " [AS_DATAFILE]";
    if (dwFlags & LOAD_LIBRARY_AS_IMAGE_RESOURCE) params << " [AS_IMAGE_RESOURCE]";

    HMODULE result = Real_LoadLibraryExW(lpLibFileName, hFile, dwFlags);

    std::ostringstream ret;
    ret << FmtPtr(result);

    LOG_API_CALL("kernel32.dll", "LoadLibraryExW", params.str(), ret.str(), ApiCategory::INJECTION);
    return result;
}

FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    std::ostringstream params;
    params << "hModule=" << FmtPtr(hModule);

    // 检查是否是按序号导入
    if (HIWORD(lpProcName) == 0) {
        params << ", Ordinal=" << LOWORD(lpProcName);
    } else {
        params << ", Proc=" << FmtStrA(lpProcName);
        // 标记敏感API的解析
        if (strcmp(lpProcName, "CreateRemoteThread") == 0 ||
            strcmp(lpProcName, "VirtualAllocEx") == 0 ||
            strcmp(lpProcName, "WriteProcessMemory") == 0 ||
            strcmp(lpProcName, "NtCreateThreadEx") == 0) {
            params << " [INJECTION_API!]";
        }
    }

    FARPROC result = Real_GetProcAddress(hModule, lpProcName);

    std::ostringstream ret;
    ret << FmtPtr((void*)result);

    LOG_API_CALL("kernel32.dll", "GetProcAddress", params.str(), ret.str(), ApiCategory::INJECTION);
    return result;
}

HHOOK WINAPI Hook_SetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
    std::ostringstream params;
    params << "HookType=" << GetHookTypeName(idHook) << "(" << idHook << ")"
           << ", HookProc=" << FmtPtr((void*)lpfn)
           << ", hMod=" << FmtPtr(hmod)
           << ", ThreadId=" << dwThreadId;

    if (dwThreadId == 0) params << " [GLOBAL HOOK]";

    HHOOK result = Real_SetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);

    std::ostringstream ret;
    ret << FmtHandle(result);
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("user32.dll", "SetWindowsHookExW", params.str(), ret.str(), ApiCategory::INJECTION);
    return result;
}

HRESULT WINAPI Hook_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv) {
    std::ostringstream params;
    params << "CLSID=... , ClsContext=" << FmtDWORD(dwClsContext);
    if (dwClsContext & CLSCTX_REMOTE_SERVER) params << " [REMOTE]";

    HRESULT result = Real_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;
    if (SUCCEEDED(result)) ret << " (SUCCESS)";

    LOG_API_CALL("ole32.dll", "CoCreateInstance", params.str(), ret.str(), ApiCategory::INJECTION);
    return result;
}

NTSTATUS NTAPI Hook_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits,
    SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {

    std::ostringstream params;
    params << "hProcess=" << FmtHandle(ProcessHandle)
           << ", StartAddr=" << FmtPtr(StartRoutine)
           << ", Argument=" << FmtPtr(Argument)
           << ", Flags=0x" << std::hex << CreateFlags;

    // 检测是否在其他进程中创建线程
    if (ProcessHandle != GetCurrentProcess()) {
        params << " [CROSS-PROCESS INJECTION!]";
    }

    NTSTATUS result = Real_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
        ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits,
        StackSize, MaximumStackSize, AttributeList);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;

    LOG_API_CALL("ntdll.dll", "NtCreateThreadEx", params.str(), ret.str(), ApiCategory::INJECTION);
    return result;
}

NTSTATUS NTAPI Hook_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
    DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {

    std::ostringstream params;
    params << "Section=" << FmtHandle(SectionHandle)
           << ", hProcess=" << FmtHandle(ProcessHandle)
           << ", Protect=0x" << std::hex << Win32Protect;

    if (ProcessHandle != GetCurrentProcess()) {
        params << " [CROSS-PROCESS!]";
    }

    NTSTATUS result = Real_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
        ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;
    if (result == 0 && BaseAddress) ret << " (Base=0x" << std::hex << (DWORD64)*BaseAddress << ")";

    LOG_API_CALL("ntdll.dll", "NtMapViewOfSection", params.str(), ret.str(), ApiCategory::INJECTION);
    return result;
}

void InstallInjectionHooks() {
    // DLL加载
    HOOK_API("LoadLibraryW", Hook_LoadLibraryW, Real_LoadLibraryW);
    HOOK_API("LoadLibraryA", Hook_LoadLibraryA, Real_LoadLibraryA);
    HOOK_API("LoadLibraryExW", Hook_LoadLibraryExW, Real_LoadLibraryExW);
    HOOK_API("LoadLibraryExA", Hook_LoadLibraryExA, Real_LoadLibraryExA);
    HOOK_API("GetProcAddress", Hook_GetProcAddress, Real_GetProcAddress);
    HOOK_API("GetModuleHandleW", Hook_GetModuleHandleW, Real_GetModuleHandleW);
    HOOK_API("GetModuleHandleA", Hook_GetModuleHandleA, Real_GetModuleHandleA);

    // 窗口钩子
    HOOK_API_USER32("SetWindowsHookExW", Hook_SetWindowsHookExW, Real_SetWindowsHookExW);
    HOOK_API_USER32("SetWindowsHookExA", Hook_SetWindowsHookExA, Real_SetWindowsHookExA);
    HOOK_API_USER32("UnhookWindowsHookEx", Hook_UnhookWindowsHookEx, Real_UnhookWindowsHookEx);
    HOOK_API_USER32("CallNextHookEx", Hook_CallNextHookEx, Real_CallNextHookEx);

    // COM
    HOOK_API_OLE32("CoCreateInstance", Hook_CoCreateInstance, Real_CoCreateInstance);
    HOOK_API_OLE32("CoGetClassObject", Hook_CoGetClassObject, Real_CoGetClassObject);
    HOOK_API_OLE32("CoCreateInstanceEx", Hook_CoCreateInstanceEx, Real_CoCreateInstanceEx);

    // 跨进程注入
    HOOK_API("CreateRemoteThreadEx", Hook_CreateRemoteThreadEx, Real_CreateRemoteThreadEx);

    // NTDLL函数
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        Real_NtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
        if (Real_NtCreateThreadEx) {
            MH_CreateHook(Real_NtCreateThreadEx, Hook_NtCreateThreadEx, (LPVOID*)&Real_NtCreateThreadEx);
            MH_EnableHook(Real_NtCreateThreadEx);
        }

        Real_NtMapViewOfSection = (PFN_NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
        if (Real_NtMapViewOfSection) {
            MH_CreateHook(Real_NtMapViewOfSection, Hook_NtMapViewOfSection, (LPVOID*)&Real_NtMapViewOfSection);
            MH_EnableHook(Real_NtMapViewOfSection);
        }
    }
}