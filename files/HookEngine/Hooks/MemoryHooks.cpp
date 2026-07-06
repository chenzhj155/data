#include "MemoryHooks.h"
#include "../HookEngine.h"
#include <sstream>

// ========== 原始函数指针 ==========
static LPVOID (WINAPI *Real_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
static LPVOID (WINAPI *Real_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
static BOOL (WINAPI *Real_VirtualFree)(LPVOID, SIZE_T, DWORD) = VirtualFree;
static BOOL (WINAPI *Real_VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD) = VirtualFreeEx;
static BOOL (WINAPI *Real_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtect;
static BOOL (WINAPI *Real_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtectEx;
static BOOL (WINAPI *Real_ReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
static BOOL (WINAPI *Real_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
static SIZE_T (WINAPI *Real_VirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) = VirtualQuery;
static SIZE_T (WINAPI *Real_VirtualQueryEx)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) = VirtualQueryEx;
static HANDLE (WINAPI *Real_CreateFileMappingW)(LPCWSTR, DWORD, DWORD, DWORD, LPVOID, DWORD, LPSECURITY_ATTRIBUTES, HANDLE) = CreateFileMappingW;
static LPVOID (WINAPI *Real_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T) = MapViewOfFile;
static BOOL (WINAPI *Real_UnmapViewOfFile)(LPCVOID) = UnmapViewOfFile;
static LPVOID (WINAPI *Real_HeapAlloc)(HANDLE, DWORD, SIZE_T) = HeapAlloc;
static BOOL (WINAPI *Real_HeapFree)(HANDLE, DWORD, LPVOID) = HeapFree;
static HANDLE (WINAPI *Real_HeapCreate)(DWORD, SIZE_T, SIZE_T) = HeapCreate;
static BOOL (WINAPI *Real_HeapDestroy)(HANDLE) = HeapDestroy;

// ========== 辅助函数 ==========
static std::string GetProtectString(DWORD protect) {
    std::vector<std::string> flags;
    if (protect & PAGE_EXECUTE)           flags.push_back("EXECUTE");
    if (protect & PAGE_EXECUTE_READ)      flags.push_back("EXECUTE_READ");
    if (protect & PAGE_EXECUTE_READWRITE) flags.push_back("EXECUTE_READWRITE [SUSPICIOUS!]");
    if (protect & PAGE_EXECUTE_WRITECOPY) flags.push_back("EXECUTE_WRITECOPY");
    if (protect & PAGE_NOACCESS)          flags.push_back("NOACCESS");
    if (protect & PAGE_READONLY)          flags.push_back("READONLY");
    if (protect & PAGE_READWRITE)         flags.push_back("READWRITE");
    if (protect & PAGE_WRITECOPY)         flags.push_back("WRITECOPY");
    if (protect & PAGE_GUARD)             flags.push_back("GUARD");
    if (protect & PAGE_NOCACHE)           flags.push_back("NOCACHE");

    std::string result = "0x" + FmtDWORD(protect).substr(2);
    if (!flags.empty()) {
        result += "(";
        for (size_t i = 0; i < flags.size(); i++) {
            if (i > 0) result += "|";
            result += flags[i];
        }
        result += ")";
    }
    return result;
}

// ========== Hook 实现 ==========
LPVOID WINAPI Hook_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    std::ostringstream params;
    params << "Addr=" << FmtPtr(lpAddress) << ", Size=0x" << std::hex << dwSize
           << ", Type=0x" << flAllocationType
           << ", Protect=" << GetProtectString(flProtect);

    // 检测可执行内存分配（可能是shellcode）
    if (flProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        params << " [EXECUTABLE MEMORY!]";
    }

    LPVOID result = Real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    std::string ret = FmtPtr(result);
    LOG_API_CALL("kernel32.dll", "VirtualAlloc", params.str(), ret, ApiCategory::MEMORY_OPERATION);
    return result;
}

LPVOID WINAPI Hook_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    std::ostringstream params;
    params << "hProcess=" << FmtHandle(hProcess) << ", Addr=" << FmtPtr(lpAddress)
           << ", Size=0x" << std::hex << dwSize
           << ", Protect=" << GetProtectString(flProtect);

    if (flProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        params << " [REMOTE EXECUTABLE!]";
    }

    LPVOID result = Real_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    LOG_API_CALL("kernel32.dll", "VirtualAllocEx", params.str(), FmtPtr(result), ApiCategory::MEMORY_OPERATION);
    return result;
}

BOOL WINAPI Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    std::ostringstream params;
    params << "Addr=" << FmtPtr(lpAddress) << ", Size=0x" << std::hex << dwSize
           << ", NewProtect=" << GetProtectString(flNewProtect);

    if (flNewProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
        params << " [SETTING EXECUTABLE!]";
    }

    BOOL result = Real_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpflOldProtect) ret << " (OldProtect=" << GetProtectString(*lpflOldProtect) << ")";

    LOG_API_CALL("kernel32.dll", "VirtualProtect", params.str(), ret.str(), ApiCategory::MEMORY_OPERATION);
    return result;
}

BOOL WINAPI Hook_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    std::ostringstream params;
    params << "hProcess=" << FmtHandle(hProcess) << ", Addr=" << FmtPtr(lpAddress)
           << ", Size=0x" << std::hex << dwSize
           << ", NewProtect=" << GetProtectString(flNewProtect);

    BOOL result = Real_VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpflOldProtect) ret << " (OldProtect=" << GetProtectString(*lpflOldProtect) << ")";

    LOG_API_CALL("kernel32.dll", "VirtualProtectEx", params.str(), ret.str(), ApiCategory::MEMORY_OPERATION);
    return result;
}

BOOL WINAPI Hook_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    std::ostringstream params;
    params << "hProcess=" << FmtHandle(hProcess) << ", Addr=" << FmtPtr((void*)lpBaseAddress)
           << ", Size=" << nSize;

    BOOL result = Real_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpNumberOfBytesRead) ret << " (Read:" << *lpNumberOfBytesRead << ")";

    LOG_API_CALL("kernel32.dll", "ReadProcessMemory", params.str(), ret.str(), ApiCategory::MEMORY_OPERATION);
    return result;
}

BOOL WINAPI Hook_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    std::ostringstream params;
    params << "hProcess=" << FmtHandle(hProcess) << ", Addr=" << FmtPtr(lpBaseAddress)
           << ", Size=" << nSize;

    // 记录写入数据的前几个字节
    if (lpBuffer && nSize > 0 && nSize <= 512) {
        params << ", Data=[";
        const BYTE* d = (const BYTE*)lpBuffer;
        for (SIZE_T i = 0; i < min(nSize, (SIZE_T)32); i++)
            params << std::hex << std::setw(2) << std::setfill('0') << (int)d[i] << " ";
        if (nSize > 32) params << "...";
        params << "]";
    }

    BOOL result = Real_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpNumberOfBytesWritten) ret << " (Written:" << *lpNumberOfBytesWritten << ")";

    LOG_API_CALL("kernel32.dll", "WriteProcessMemory", params.str(), ret.str(), ApiCategory::MEMORY_OPERATION);
    return result;
}

LPVOID WINAPI Hook_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {
    std::ostringstream params;
    params << "hMapping=" << FmtHandle(hFileMappingObject) << ", Access=0x" << std::hex << dwDesiredAccess
           << ", Size=" << dwNumberOfBytesToMap;

    LPVOID result = Real_MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);

    LOG_API_CALL("kernel32.dll", "MapViewOfFile", params.str(), FmtPtr(result), ApiCategory::MEMORY_OPERATION);
    return result;
}

void InstallMemoryHooks() {
    HOOK_API("VirtualAlloc", Hook_VirtualAlloc, Real_VirtualAlloc);
    HOOK_API("VirtualAllocEx", Hook_VirtualAllocEx, Real_VirtualAllocEx);
    HOOK_API("VirtualFree", Hook_VirtualFree, Real_VirtualFree);
    HOOK_API("VirtualFreeEx", Hook_VirtualFreeEx, Real_VirtualFreeEx);
    HOOK_API("VirtualProtect", Hook_VirtualProtect, Real_VirtualProtect);
    HOOK_API("VirtualProtectEx", Hook_VirtualProtectEx, Real_VirtualProtectEx);
    HOOK_API("ReadProcessMemory", Hook_ReadProcessMemory, Real_ReadProcessMemory);
    HOOK_API("WriteProcessMemory", Hook_WriteProcessMemory, Real_WriteProcessMemory);
    HOOK_API("VirtualQuery", Hook_VirtualQuery, Real_VirtualQuery);
    HOOK_API("VirtualQueryEx", Hook_VirtualQueryEx, Real_VirtualQueryEx);
    HOOK_API("CreateFileMappingW", Hook_CreateFileMappingW, Real_CreateFileMappingW);
    HOOK_API("MapViewOfFile", Hook_MapViewOfFile, Real_MapViewOfFile);
    HOOK_API("UnmapViewOfFile", Hook_UnmapViewOfFile, Real_UnmapViewOfFile);
    HOOK_API("HeapAlloc", Hook_HeapAlloc, Real_HeapAlloc);
    HOOK_API("HeapFree", Hook_HeapFree, Real_HeapFree);
    HOOK_API("HeapCreate", Hook_HeapCreate, Real_HeapCreate);
    HOOK_API("HeapDestroy", Hook_HeapDestroy, Real_HeapDestroy);
}