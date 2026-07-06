#pragma once
#include <windows.h>

// 调试器检测
BOOL WINAPI Hook_IsDebuggerPresent();
BOOL WINAPI Hook_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent);

// 调试器交互
BOOL WINAPI Hook_DebugActiveProcess(DWORD dwProcessId);
BOOL WINAPI Hook_DebugActiveProcessStop(DWORD dwProcessId);
void WINAPI Hook_DebugBreak();
void WINAPI Hook_OutputDebugStringA(LPCSTR lpOutputString);
void WINAPI Hook_OutputDebugStringW(LPCWSTR lpOutputString);

// NTDLL 调试相关
NTSTATUS NTAPI Hook_NtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI Hook_NtSetInformationThread(HANDLE ThreadHandle, DWORD ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
NTSTATUS NTAPI Hook_NtQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI Hook_NtClose(HANDLE Handle);

// 时间检测（反沙箱/反调试）
DWORD WINAPI Hook_GetTickCount();
ULONGLONG WINAPI Hook_GetTickCount64();
BOOL WINAPI Hook_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount);
NTSTATUS NTAPI Hook_NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);

// 异常处理（反调试）
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hook_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
LONG WINAPI Hook_UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo);
void WINAPI Hook_RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments);
NTSTATUS NTAPI Hook_NtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord, BOOL FirstChance);

// 其他反调试
BOOL WINAPI Hook_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
BOOL WINAPI Hook_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
HANDLE WINAPI Hook_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);

void InstallAntiDebugHooks();