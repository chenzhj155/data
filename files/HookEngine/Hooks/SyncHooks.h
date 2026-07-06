#pragma once
#include <windows.h>

HANDLE WINAPI Hook_CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
HANDLE WINAPI Hook_CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
HANDLE WINAPI Hook_OpenMutexW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName);
BOOL WINAPI Hook_ReleaseMutex(HANDLE hMutex);
HANDLE WINAPI Hook_CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
HANDLE WINAPI Hook_CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
BOOL WINAPI Hook_SetEvent(HANDLE hEvent);
BOOL WINAPI Hook_ResetEvent(HANDLE hEvent);
DWORD WINAPI Hook_WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DWORD WINAPI Hook_WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);

void InstallSyncHooks();