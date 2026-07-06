#pragma once
#include <windows.h>

// DLL注入
HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR lpLibFileName);
HMODULE WINAPI Hook_LoadLibraryA(LPCSTR lpLibFileName);
HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE WINAPI Hook_GetModuleHandleW(LPCWSTR lpModuleName);
HMODULE WINAPI Hook_GetModuleHandleA(LPCSTR lpModuleName);

// 窗口钩子注入
HHOOK WINAPI Hook_SetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);
HHOOK WINAPI Hook_SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);
BOOL WINAPI Hook_UnhookWindowsHookEx(HHOOK hhk);
LRESULT WINAPI Hook_CallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);

// COM相关注入
HRESULT WINAPI Hook_CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);
HRESULT WINAPI Hook_CoGetClassObject(REFCLSID rclsid, DWORD dwClsContext, LPVOID pvReserved, REFIID riid, LPVOID* ppv);
HRESULT WINAPI Hook_CoCreateInstanceEx(REFCLSID Clsid, IUnknown* punkOuter, DWORD dwClsCtx, COSERVERINFO* pServerInfo, ULONG cmq, MULTI_QI* pResults);

// 其他注入技术
BOOL WINAPI Hook_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
BOOL WINAPI Hook_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
HANDLE WINAPI Hook_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE WINAPI Hook_CreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId);
DWORD WINAPI Hook_QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
NTSTATUS NTAPI Hook_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

// 反射式DLL注入相关
NTSTATUS NTAPI Hook_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
HANDLE WINAPI Hook_CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);
HANDLE WINAPI Hook_OpenFileMappingW(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName);

void InstallInjectionHooks();