#pragma once
#include <windows.h>

LPVOID WINAPI Hook_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID WINAPI Hook_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL WINAPI Hook_VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL WINAPI Hook_VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL WINAPI Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL WINAPI Hook_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL WINAPI Hook_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
BOOL WINAPI Hook_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
SIZE_T WINAPI Hook_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
SIZE_T WINAPI Hook_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
HANDLE WINAPI Hook_CreateFileMappingW(LPCWSTR lpName, DWORD flProtect, DWORD dwMaximumSizeHigh,
    DWORD dwMaximumSizeLow, LPVOID lpFileMappingAttributes, DWORD flDesiredAccess, LPSECURITY_ATTRIBUTES lpSA, HANDLE hTemplateFile);
LPVOID WINAPI Hook_MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
BOOL WINAPI Hook_UnmapViewOfFile(LPCVOID lpBaseAddress);
LPVOID WINAPI Hook_HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
BOOL WINAPI Hook_HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
HANDLE WINAPI Hook_HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL WINAPI Hook_HeapDestroy(HANDLE hHeap);

void InstallMemoryHooks();