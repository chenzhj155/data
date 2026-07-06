#include "FileHooks.h"
#include "../HookEngine.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

// ========== 原始函数指针 ==========
static HANDLE (WINAPI *Real_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
static HANDLE (WINAPI *Real_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
static BOOL (WINAPI *Real_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
static BOOL (WINAPI *Real_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
static BOOL (WINAPI *Real_DeleteFileW)(LPCWSTR) = DeleteFileW;
static BOOL (WINAPI *Real_DeleteFileA)(LPCSTR) = DeleteFileA;
static BOOL (WINAPI *Real_CopyFileW)(LPCWSTR, LPCWSTR, BOOL) = CopyFileW;
static BOOL (WINAPI *Real_MoveFileW)(LPCWSTR, LPCWSTR) = MoveFileW;
static BOOL (WINAPI *Real_CreateDirectoryW)(LPCWSTR, LPSECURITY_ATTRIBUTES) = CreateDirectoryW;
static BOOL (WINAPI *Real_RemoveDirectoryW)(LPCWSTR) = RemoveDirectoryW;
static HANDLE (WINAPI *Real_FindFirstFileW)(LPCWSTR, LPWIN32_FIND_DATAW) = FindFirstFileW;
static BOOL (WINAPI *Real_FindNextFileW)(HANDLE, LPWIN32_FIND_DATAW) = FindNextFileW;
static BOOL (WINAPI *Real_FindClose)(HANDLE) = FindClose;
static DWORD (WINAPI *Real_GetFileAttributesW)(LPCWSTR) = GetFileAttributesW;
static BOOL (WINAPI *Real_SetFileAttributesW)(LPCWSTR, DWORD) = SetFileAttributesW;

// ========== 辅助函数 ==========
static const char* GetCreationDisposition(DWORD dw) {
    switch (dw) {
        case CREATE_NEW:        return "CREATE_NEW";
        case CREATE_ALWAYS:     return "CREATE_ALWAYS";
        case OPEN_EXISTING:     return "OPEN_EXISTING";
        case OPEN_ALWAYS:       return "OPEN_ALWAYS";
        case TRUNCATE_EXISTING: return "TRUNCATE_EXISTING";
        default:                return "UNKNOWN";
    }
}

// ========== Hook 实现 ==========

HANDLE WINAPI Hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreationDisp, DWORD dwFlags, HANDLE hTemplate) {

    std::ostringstream params;
    params << "File=" << FmtStrW(lpFileName)
           << ", Disposition=" << GetCreationDisposition(dwCreationDisp)
           << ", Access=" << FmtDWORD(dwDesiredAccess);

    HANDLE result = Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSA, dwCreationDisp, dwFlags, hTemplate);

    std::ostringstream ret;
    if (result == INVALID_HANDLE_VALUE)
        ret << "INVALID_HANDLE_VALUE(Err:" << GetLastError() << ")";
    else
        ret << FmtHandle(result);

    LOG_API_CALL("kernel32.dll", "CreateFileW", params.str(), ret.str(), ApiCategory::FILE_OPERATION);
    return result;
}

HANDLE WINAPI Hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCreationDisp, DWORD dwFlags, HANDLE hTemplate) {

    std::ostringstream params;
    params << "File=" << FmtStrA(lpFileName)
           << ", Disposition=" << GetCreationDisposition(dwCreationDisp)
           << ", Access=" << FmtDWORD(dwDesiredAccess);

    HANDLE result = Real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSA, dwCreationDisp, dwFlags, hTemplate);

    std::ostringstream ret;
    if (result == INVALID_HANDLE_VALUE)
        ret << "INVALID_HANDLE_VALUE(Err:" << GetLastError() << ")";
    else
        ret << FmtHandle(result);

    LOG_API_CALL("kernel32.dll", "CreateFileA", params.str(), ret.str(), ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nBytes, LPDWORD lpWritten, LPOVERLAPPED lpOL) {
    std::ostringstream params;
    params << "hFile=" << FmtHandle(hFile) << ", Bytes=" << nBytes;
    if (lpBuffer && nBytes > 0 && nBytes <= 256) {
        params << ", Data=[";
        const BYTE* d = (const BYTE*)lpBuffer;
        for (DWORD i = 0; i < min(nBytes, 32u); i++)
            params << std::hex << std::setw(2) << std::setfill('0') << (int)d[i] << " ";
        if (nBytes > 32) params << "...";
        params << "]";
    }

    BOOL result = Real_WriteFile(hFile, lpBuffer, nBytes, lpWritten, lpOL);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpWritten) ret << " (Written:" << *lpWritten << ")";
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("kernel32.dll", "WriteFile", params.str(), ret.str(), ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nBytes, LPDWORD lpRead, LPOVERLAPPED lpOL) {
    std::ostringstream params;
    params << "hFile=" << FmtHandle(hFile) << ", MaxBytes=" << nBytes;

    BOOL result = Real_ReadFile(hFile, lpBuffer, nBytes, lpRead, lpOL);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpRead) {
        ret << " (Read:" << *lpRead << ")";
        if (*lpRead > 0 && *lpRead <= 256 && lpBuffer) {
            ret << " Data=[";
            const BYTE* d = (const BYTE*)lpBuffer;
            for (DWORD i = 0; i < min(*lpRead, 32u); i++)
                ret << std::hex << std::setw(2) << std::setfill('0') << (int)d[i] << " ";
            if (*lpRead > 32) ret << "...";
            ret << "]";
        }
    }

    LOG_API_CALL("kernel32.dll", "ReadFile", params.str(), ret.str(), ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_DeleteFileW(LPCWSTR lpFileName) {
    std::string params = "File=" + FmtStrW(lpFileName);
    BOOL result = Real_DeleteFileW(lpFileName);
    std::string ret = FmtBOOL(result);
    if (!result) ret += " (Err:" + std::to_string(GetLastError()) + ")";
    LOG_API_CALL("kernel32.dll", "DeleteFileW", params, ret, ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_DeleteFileA(LPCSTR lpFileName) {
    std::string params = "File=" + FmtStrA(lpFileName);
    BOOL result = Real_DeleteFileA(lpFileName);
    std::string ret = FmtBOOL(result);
    if (!result) ret += " (Err:" + std::to_string(GetLastError()) + ")";
    LOG_API_CALL("kernel32.dll", "DeleteFileA", params, ret, ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) {
    std::ostringstream params;
    params << "From=" << FmtStrW(lpExistingFileName)
           << ", To=" << FmtStrW(lpNewFileName)
           << ", FailIfExists=" << FmtBOOL(bFailIfExists);

    BOOL result = Real_CopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);

    std::string ret = FmtBOOL(result);
    if (!result) ret += " (Err:" + std::to_string(GetLastError()) + ")";

    LOG_API_CALL("kernel32.dll", "CopyFileW", params.str(), ret, ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) {
    std::ostringstream params;
    params << "From=" << FmtStrW(lpExistingFileName) << ", To=" << FmtStrW(lpNewFileName);

    BOOL result = Real_MoveFileW(lpExistingFileName, lpNewFileName);

    std::string ret = FmtBOOL(result);
    if (!result) ret += " (Err:" + std::to_string(GetLastError()) + ")";

    LOG_API_CALL("kernel32.dll", "MoveFileW", params.str(), ret, ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
    std::string params = "Path=" + FmtStrW(lpPathName);
    BOOL result = Real_CreateDirectoryW(lpPathName, lpSecurityAttributes);
    std::string ret = FmtBOOL(result);
    if (!result) ret += " (Err:" + std::to_string(GetLastError()) + ")";
    LOG_API_CALL("kernel32.dll", "CreateDirectoryW", params, ret, ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_RemoveDirectoryW(LPCWSTR lpPathName) {
    std::string params = "Path=" + FmtStrW(lpPathName);
    BOOL result = Real_RemoveDirectoryW(lpPathName);
    std::string ret = FmtBOOL(result);
    if (!result) ret += " (Err:" + std::to_string(GetLastError()) + ")";
    LOG_API_CALL("kernel32.dll", "RemoveDirectoryW", params, ret, ApiCategory::FILE_OPERATION);
    return result;
}

HANDLE WINAPI Hook_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    std::string params = "Pattern=" + FmtStrW(lpFileName);
    HANDLE result = Real_FindFirstFileW(lpFileName, lpFindFileData);

    std::ostringstream ret;
    if (result == INVALID_HANDLE_VALUE) {
        ret << "INVALID_HANDLE_VALUE(Err:" << GetLastError() << ")";
    } else {
        ret << FmtHandle(result);
        if (lpFindFileData) {
            std::wstring w(lpFindFileData->cFileName);
            std::string name(w.begin(), w.end());
            ret << " (Found:" << name << ")";
        }
    }

    LOG_API_CALL("kernel32.dll", "FindFirstFileW", params, ret.str(), ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    std::string params = "hFind=" + FmtHandle(hFindFile);
    BOOL result = Real_FindNextFileW(hFindFile, lpFindFileData);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && lpFindFileData) {
        std::wstring w(lpFindFileData->cFileName);
        std::string name(w.begin(), w.end());
        ret << " (File:" << name << ")";
    }

    LOG_API_CALL("kernel32.dll", "FindNextFileW", params, ret.str(), ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_FindClose(HANDLE hFindFile) {
    std::string params = "hFind=" + FmtHandle(hFindFile);
    BOOL result = Real_FindClose(hFindFile);
    LOG_API_CALL("kernel32.dll", "FindClose", params, FmtBOOL(result), ApiCategory::FILE_OPERATION);
    return result;
}

DWORD WINAPI Hook_GetFileAttributesW(LPCWSTR lpFileName) {
    std::string params = "File=" + FmtStrW(lpFileName);
    DWORD result = Real_GetFileAttributesW(lpFileName);

    std::ostringstream ret;
    if (result == INVALID_FILE_ATTRIBUTES)
        ret << "INVALID_FILE_ATTRIBUTES(Err:" << GetLastError() << ")";
    else
        ret << "0x" << std::hex << result;

    LOG_API_CALL("kernel32.dll", "GetFileAttributesW", params, ret.str(), ApiCategory::FILE_OPERATION);
    return result;
}

BOOL WINAPI Hook_SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes) {
    std::ostringstream params;
    params << "File=" << FmtStrW(lpFileName) << ", Attr=0x" << std::hex << dwFileAttributes;
    BOOL result = Real_SetFileAttributesW(lpFileName, dwFileAttributes);
    LOG_API_CALL("kernel32.dll", "SetFileAttributesW", params.str(), FmtBOOL(result), ApiCategory::FILE_OPERATION);
    return result;
}

void InstallFileHooks() {
    HOOK_API("CreateFileW", Hook_CreateFileW, Real_CreateFileW);
    HOOK_API("CreateFileA", Hook_CreateFileA, Real_CreateFileA);
    HOOK_API("WriteFile", Hook_WriteFile, Real_WriteFile);
    HOOK_API("ReadFile", Hook_ReadFile, Real_ReadFile);
    HOOK_API("DeleteFileW", Hook_DeleteFileW, Real_DeleteFileW);
    HOOK_API("DeleteFileA", Hook_DeleteFileA, Real_DeleteFileA);
    HOOK_API("CopyFileW", Hook_CopyFileW, Real_CopyFileW);
    HOOK_API("MoveFileW", Hook_MoveFileW, Real_MoveFileW);
    HOOK_API("CreateDirectoryW", Hook_CreateDirectoryW, Real_CreateDirectoryW);
    HOOK_API("RemoveDirectoryW", Hook_RemoveDirectoryW, Real_RemoveDirectoryW);
    HOOK_API("FindFirstFileW", Hook_FindFirstFileW, Real_FindFirstFileW);
    HOOK_API("FindNextFileW", Hook_FindNextFileW, Real_FindNextFileW);
    HOOK_API("FindClose", Hook_FindClose, Real_FindClose);
    HOOK_API("GetFileAttributesW", Hook_GetFileAttributesW, Real_GetFileAttributesW);
    HOOK_API("SetFileAttributesW", Hook_SetFileAttributesW, Real_SetFileAttributesW);
}