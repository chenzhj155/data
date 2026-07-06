#pragma once
#include <windows.h>

// 系统信息
void WINAPI Hook_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
void WINAPI Hook_GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo);
void WINAPI Hook_GetSystemTime(LPSYSTEMTIME lpSystemTime);
void WINAPI Hook_GetLocalTime(LPSYSTEMTIME lpSystemTime);
DWORD WINAPI Hook_GetVersion();
BOOL WINAPI Hook_GetVersionExW(LPOSVERSIONINFOW lpVersionInformation);
BOOL WINAPI Hook_GetVersionExA(LPOSVERSIONINFOA lpVersionInformation);
NTSTATUS NTAPI Hook_RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

// 计算机信息
BOOL WINAPI Hook_GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize);
BOOL WINAPI Hook_GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
BOOL WINAPI Hook_GetComputerNameExW(COMPUTER_NAME_FORMAT NameType, LPWSTR lpBuffer, LPDWORD nSize);
BOOL WINAPI Hook_GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer);
BOOL WINAPI Hook_GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer);

// 进程信息
DWORD WINAPI Hook_GetCurrentProcessId();
DWORD WINAPI Hook_GetProcessId(HANDLE Process);
BOOL WINAPI Hook_GetProcessTimes(HANDLE hProcess, LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime);
BOOL WINAPI Hook_GetProcessIoCounters(HANDLE hProcess, PIO_COUNTERS lpIoCounters);
DWORD WINAPI Hook_GetProcessHandleCount(HANDLE hProcess);
DWORD WINAPI Hook_GetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize);
DWORD WINAPI Hook_GetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize);
BOOL WINAPI Hook_EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
DWORD WINAPI Hook_GetModuleBaseNameW(HANDLE hProcess, HMODULE hModule, LPWSTR lpBaseName, DWORD nSize);

// 系统信息 (NTDLL)
NTSTATUS NTAPI Hook_NtQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

// 权限相关
BOOL WINAPI Hook_OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
BOOL WINAPI Hook_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
BOOL WINAPI Hook_LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
BOOL WINAPI Hook_DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
BOOL WINAPI Hook_ImpersonateLoggedOnUser(HANDLE hToken);
BOOL WINAPI Hook_RevertToSelf();

// 服务管理
SC_HANDLE WINAPI Hook_OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
SC_HANDLE WINAPI Hook_OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
SC_HANDLE WINAPI Hook_CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword);
BOOL WINAPI Hook_StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);
BOOL WINAPI Hook_ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
BOOL WINAPI Hook_DeleteService(SC_HANDLE hService);

void InstallSystemInfoHooks();