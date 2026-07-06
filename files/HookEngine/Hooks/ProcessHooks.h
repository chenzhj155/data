#pragma once
#include <windows.h>

BOOL WINAPI Hook_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI Hook_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

HANDLE WINAPI Hook_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL WINAPI Hook_TerminateProcess(HANDLE hProcess, UINT uExitCode);
void WINAPI Hook_ExitProcess(UINT uExitCode);
DWORD WINAPI Hook_GetProcessId(HANDLE Process);
BOOL WINAPI Hook_GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
BOOL WINAPI Hook_SetProcessDEPPolicy(DWORD dwDEPPolicy);

void InstallProcessHooks();