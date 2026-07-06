#pragma once
#include <windows.h>

HANDLE WINAPI Hook_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE WINAPI Hook_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE WINAPI Hook_CreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
    DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);
HANDLE WINAPI Hook_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
DWORD WINAPI Hook_SuspendThread(HANDLE hThread);
DWORD WINAPI Hook_ResumeThread(HANDLE hThread);
BOOL WINAPI Hook_TerminateThread(HANDLE hThread, DWORD dwExitCode);
BOOL WINAPI Hook_GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
BOOL WINAPI Hook_SetThreadContext(HANDLE hThread, const CONTEXT* lpContext);
DWORD WINAPI Hook_QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);

void InstallThreadHooks();