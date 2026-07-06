#pragma once
#include <windows.h>

// 文件操作 Hook 函数声明
HANDLE WINAPI Hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

HANDLE WINAPI Hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

BOOL WINAPI Hook_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

BOOL WINAPI Hook_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

BOOL WINAPI Hook_DeleteFileW(LPCWSTR lpFileName);
BOOL WINAPI Hook_DeleteFileA(LPCSTR lpFileName);
BOOL WINAPI Hook_CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists);
BOOL WINAPI Hook_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);
BOOL WINAPI Hook_CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL WINAPI Hook_RemoveDirectoryW(LPCWSTR lpPathName);
HANDLE WINAPI Hook_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WINAPI Hook_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WINAPI Hook_FindClose(HANDLE hFindFile);
DWORD WINAPI Hook_GetFileAttributesW(LPCWSTR lpFileName);
BOOL WINAPI Hook_SetFileAttributesW(LPCWSTR lpFileName, DWORD dwFileAttributes);

void InstallFileHooks();