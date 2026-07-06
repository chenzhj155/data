#include "Config.h"

std::vector<ApiDef> GetAllMonitoredApis() {
    std::vector<ApiDef> apis;

    // ===== 文件操作 =====
    const char* fileApis[][2] = {
        {"kernel32.dll","CreateFileA"}, {"kernel32.dll","CreateFileW"}, {"kernel32.dll","CreateFile2"},
        {"kernel32.dll","OpenFile"}, {"kernel32.dll","OpenFileById"},
        {"ntdll.dll","NtCreateFile"}, {"ntdll.dll","NtOpenFile"},
        {"kernel32.dll","ReadFile"}, {"kernel32.dll","ReadFileEx"},
        {"kernel32.dll","WriteFile"}, {"kernel32.dll","WriteFileEx"},
        {"kernel32.dll","SetFilePointer"}, {"kernel32.dll","SetFilePointerEx"},
        {"ntdll.dll","NtReadFile"}, {"ntdll.dll","NtWriteFile"},
        {"kernel32.dll","DeleteFileA"}, {"kernel32.dll","DeleteFileW"},
        {"ntdll.dll","NtDeleteFile"},
        {"kernel32.dll","MoveFileA"}, {"kernel32.dll","MoveFileW"},
        {"kernel32.dll","MoveFileExA"}, {"kernel32.dll","MoveFileExW"},
        {"kernel32.dll","CopyFileA"}, {"kernel32.dll","CopyFileW"},
        {"kernel32.dll","CopyFileExA"}, {"kernel32.dll","CopyFileExW"},
        {"kernel32.dll","GetFileAttributesA"}, {"kernel32.dll","GetFileAttributesW"},
        {"kernel32.dll","SetFileAttributesA"}, {"kernel32.dll","SetFileAttributesW"},
        {"kernel32.dll","GetFileSize"}, {"kernel32.dll","GetFileSizeEx"},
        {"ntdll.dll","NtQueryInformationFile"}, {"ntdll.dll","NtSetInformationFile"},
        {"kernel32.dll","CreateDirectoryA"}, {"kernel32.dll","CreateDirectoryW"},
        {"kernel32.dll","RemoveDirectoryA"}, {"kernel32.dll","RemoveDirectoryW"},
        {"kernel32.dll","FindFirstFileA"}, {"kernel32.dll","FindFirstFileW"},
        {"kernel32.dll","FindNextFileA"}, {"kernel32.dll","FindNextFileW"},
        {"ntdll.dll","NtQueryDirectoryFile"},
        {"kernel32.dll","CloseHandle"},
        {"kernel32.dll","GetTempPathA"}, {"kernel32.dll","GetTempPathW"},
        {"kernel32.dll","GetTempFileNameA"}, {"kernel32.dll","GetTempFileNameW"},
        {"kernel32.dll","FlushFileBuffers"},
        {"kernel32.dll","LockFile"}, {"kernel32.dll","UnlockFile"},
        {"kernel32.dll","SetEndOfFile"},
        {"kernel32.dll","GetFileInformationByHandle"},
        {"kernel32.dll","GetFileType"},
        {"kernel32.dll","GetDriveTypeA"}, {"kernel32.dll","GetDriveTypeW"},
        {"kernel32.dll","GetLogicalDrives"},
        {"kernel32.dll","GetDiskFreeSpaceA"}, {"kernel32.dll","GetDiskFreeSpaceW"},
        {"kernel32.dll","GetDiskFreeSpaceExA"}, {"kernel32.dll","GetDiskFreeSpaceExW"},
        {"kernel32.dll","SetCurrentDirectoryA"}, {"kernel32.dll","SetCurrentDirectoryW"},
        {"kernel32.dll","GetCurrentDirectoryA"}, {"kernel32.dll","GetCurrentDirectoryW"},
    };
    for (auto& api : fileApis)
        apis.push_back({api[0], api[1], ApiCategory::FILE_OPERATION});

    // ===== 注册表操作 =====
    const char* regApis[][2] = {
        {"advapi32.dll","RegOpenKeyExA"}, {"advapi32.dll","RegOpenKeyExW"},
        {"advapi32.dll","RegCreateKeyExA"}, {"advapi32.dll","RegCreateKeyExW"},
        {"advapi32.dll","RegDeleteKeyA"}, {"advapi32.dll","RegDeleteKeyW"},
        {"advapi32.dll","RegDeleteKeyExA"}, {"advapi32.dll","RegDeleteKeyExW"},
        {"advapi32.dll","RegCloseKey"},
        {"ntdll.dll","NtOpenKey"}, {"ntdll.dll","NtCreateKey"}, {"ntdll.dll","NtDeleteKey"},
        {"advapi32.dll","RegSetValueExA"}, {"advapi32.dll","RegSetValueExW"},
        {"advapi32.dll","RegQueryValueExA"}, {"advapi32.dll","RegQueryValueExW"},
        {"advapi32.dll","RegDeleteValueA"}, {"advapi32.dll","RegDeleteValueW"},
        {"ntdll.dll","NtSetValueKey"}, {"ntdll.dll","NtQueryValueKey"},
        {"advapi32.dll","RegEnumKeyExA"}, {"advapi32.dll","RegEnumKeyExW"},
        {"advapi32.dll","RegEnumValueA"}, {"advapi32.dll","RegEnumValueW"},
        {"ntdll.dll","NtEnumerateKey"}, {"ntdll.dll","NtEnumerateValueKey"},
        {"advapi32.dll","RegQueryInfoKeyA"}, {"advapi32.dll","RegQueryInfoKeyW"},
        {"ntdll.dll","NtQueryKey"},
        {"advapi32.dll","RegGetKeySecurity"}, {"advapi32.dll","RegSetKeySecurity"},
        {"advapi32.dll","RegConnectRegistryA"}, {"advapi32.dll","RegConnectRegistryW"},
        {"advapi32.dll","RegLoadKeyA"}, {"advapi32.dll","RegLoadKeyW"},
        {"advapi32.dll","RegUnLoadKeyA"}, {"advapi32.dll","RegUnLoadKeyW"},
        {"advapi32.dll","RegSaveKeyA"}, {"advapi32.dll","RegSaveKeyW"},
        {"advapi32.dll","RegRestoreKeyA"}, {"advapi32.dll","RegRestoreKeyW"},
        {"advapi32.dll","RegReplaceKeyA"}, {"advapi32.dll","RegReplaceKeyW"},
        {"advapi32.dll","RegFlushKey"},
        {"advapi32.dll","RegNotifyChangeKeyValue"},
    };
    for (auto& api : regApis)
        apis.push_back({api[0], api[1], ApiCategory::REGISTRY_OPERATION});

    // ===== 内存操作 =====
    const char* memApis[][2] = {
        {"kernel32.dll","VirtualAlloc"}, {"kernel32.dll","VirtualAllocEx"},
        {"kernel32.dll","HeapAlloc"}, {"kernel32.dll","LocalAlloc"}, {"kernel32.dll","GlobalAlloc"},
        {"ntdll.dll","NtAllocateVirtualMemory"}, {"ntdll.dll","RtlAllocateHeap"},
        {"kernel32.dll","VirtualFree"}, {"kernel32.dll","VirtualFreeEx"}, {"kernel32.dll","HeapFree"},
        {"ntdll.dll","NtFreeVirtualMemory"}, {"ntdll.dll","RtlFreeHeap"},
        {"kernel32.dll","VirtualProtect"}, {"kernel32.dll","VirtualProtectEx"},
        {"ntdll.dll","NtProtectVirtualMemory"},
        {"kernel32.dll","RtlMoveMemory"}, {"kernel32.dll","RtlCopyMemory"},
        {"kernel32.dll","RtlFillMemory"}, {"kernel32.dll","RtlZeroMemory"},
        {"kernel32.dll","CreateFileMappingA"}, {"kernel32.dll","CreateFileMappingW"},
        {"kernel32.dll","MapViewOfFile"}, {"kernel32.dll","MapViewOfFileEx"},
        {"kernel32.dll","UnmapViewOfFile"},
        {"ntdll.dll","NtCreateSection"}, {"ntdll.dll","NtMapViewOfSection"},
        {"kernel32.dll","VirtualQuery"}, {"kernel32.dll","VirtualQueryEx"},
        {"ntdll.dll","NtQueryVirtualMemory"},
        {"kernel32.dll","ReadProcessMemory"}, {"kernel32.dll","WriteProcessMemory"},
        {"ntdll.dll","NtReadVirtualMemory"}, {"ntdll.dll","NtWriteVirtualMemory"},
        {"kernel32.dll","HeapCreate"}, {"kernel32.dll","HeapDestroy"},
        {"kernel32.dll","HeapReAlloc"}, {"kernel32.dll","HeapSize"},
        {"kernel32.dll","GlobalLock"}, {"kernel32.dll","GlobalUnlock"},
        {"kernel32.dll","LocalLock"}, {"kernel32.dll","LocalUnlock"},
        {"kernel32.dll","IsBadReadPtr"}, {"kernel32.dll","IsBadWritePtr"},
        {"kernel32.dll","IsBadCodePtr"},
    };
    for (auto& api : memApis)
        apis.push_back({api[0], api[1], ApiCategory::MEMORY_OPERATION});

    // ===== 进程操作 =====
    const char* procApis[][2] = {
        {"kernel32.dll","CreateProcessA"}, {"kernel32.dll","CreateProcessW"},
        {"kernel32.dll","CreateProcessAsUserA"}, {"kernel32.dll","CreateProcessAsUserW"},
        {"kernel32.dll","CreateProcessWithLogonW"}, {"kernel32.dll","CreateProcessWithTokenW"},
        {"advapi32.dll","CreateProcessAsUserA"}, {"advapi32.dll","CreateProcessAsUserW"},
        {"ntdll.dll","NtCreateProcess"}, {"ntdll.dll","NtCreateProcessEx"}, {"ntdll.dll","NtCreateUserProcess"},
        {"kernel32.dll","OpenProcess"}, {"kernel32.dll","GetCurrentProcess"},
        {"ntdll.dll","NtOpenProcess"},
        {"kernel32.dll","TerminateProcess"}, {"kernel32.dll","ExitProcess"},
        {"ntdll.dll","NtTerminateProcess"},
        {"kernel32.dll","GetProcessId"}, {"kernel32.dll","GetProcessTimes"},
        {"ntdll.dll","NtQueryInformationProcess"}, {"ntdll.dll","NtSetInformationProcess"},
        {"kernel32.dll","EnumProcesses"},
        {"kernel32.dll","Process32FirstW"}, {"kernel32.dll","Process32NextW"},
        {"psapi.dll","EnumProcesses"},
        {"kernel32.dll","CreateToolhelp32Snapshot"},
        {"kernel32.dll","GetExitCodeProcess"},
        {"kernel32.dll","GetPriorityClass"}, {"kernel32.dll","SetPriorityClass"},
        {"kernel32.dll","GetProcessHandleCount"},
        {"kernel32.dll","GetProcessWorkingSetSize"},
        {"shell32.dll","ShellExecuteA"}, {"shell32.dll","ShellExecuteW"},
        {"shell32.dll","ShellExecuteExA"}, {"shell32.dll","ShellExecuteExW"},
        {"kernel32.dll","WinExec"},
    };
    for (auto& api : procApis)
        apis.push_back({api[0], api[1], ApiCategory::PROCESS_CREATION});

    // ===== 线程操作 =====
    const char* threadApis[][2] = {
        {"kernel32.dll","CreateThread"}, {"kernel32.dll","CreateRemoteThread"}, {"kernel32.dll","CreateRemoteThreadEx"},
        {"ntdll.dll","NtCreateThreadEx"}, {"ntdll.dll","RtlCreateUserThread"},
        {"kernel32.dll","OpenThread"}, {"kernel32.dll","GetCurrentThread"}, {"ntdll.dll","NtOpenThread"},
        {"kernel32.dll","SuspendThread"}, {"kernel32.dll","ResumeThread"},
        {"kernel32.dll","TerminateThread"}, {"kernel32.dll","ExitThread"},
        {"ntdll.dll","NtSuspendThread"}, {"ntdll.dll","NtResumeThread"}, {"ntdll.dll","NtTerminateThread"},
        {"kernel32.dll","GetThreadContext"}, {"kernel32.dll","SetThreadContext"},
        {"ntdll.dll","NtGetContextThread"}, {"ntdll.dll","NtSetContextThread"},
        {"kernel32.dll","GetThreadId"}, {"kernel32.dll","GetThreadTimes"},
        {"ntdll.dll","NtQueryInformationThread"},
        {"kernel32.dll","SetThreadPriority"}, {"kernel32.dll","GetThreadPriority"},
        {"kernel32.dll","TlsAlloc"}, {"kernel32.dll","TlsFree"}, {"kernel32.dll","TlsGetValue"}, {"kernel32.dll","TlsSetValue"},
        {"kernel32.dll","QueueUserAPC"}, {"ntdll.dll","NtQueueApcThread"}, {"ntdll.dll","NtQueueApcThreadEx"},
        {"kernel32.dll","Thread32First"}, {"kernel32.dll","Thread32Next"},
    };
    for (auto& api : threadApis)
        apis.push_back({api[0], api[1], ApiCategory::THREAD_OPERATION});

    // ===== 纤程操作 =====
    const char* fiberApis[][2] = {
        {"kernel32.dll","CreateFiber"}, {"kernel32.dll","CreateFiberEx"},
        {"kernel32.dll","DeleteFiber"},
        {"kernel32.dll","ConvertThreadToFiber"}, {"kernel32.dll","ConvertThreadToFiberEx"},
        {"kernel32.dll","ConvertFiberToThread"}, {"kernel32.dll","SwitchToFiber"},
        {"kernel32.dll","FlsAlloc"}, {"kernel32.dll","FlsFree"},
        {"kernel32.dll","FlsGetValue"}, {"kernel32.dll","FlsSetValue"},
        {"kernel32.dll","IsThreadAFiber"},
    };
    for (auto& api : fiberApis)
        apis.push_back({api[0], api[1], ApiCategory::FIBER_OPERATION});

    // ===== 窗口操作 =====
    const char* winApis[][2] = {
        {"user32.dll","CreateWindowExA"}, {"user32.dll","CreateWindowExW"},
        {"user32.dll","CreateWindowA"}, {"user32.dll","CreateWindowW"},
        {"user32.dll","DialogBoxParamA"}, {"user32.dll","DialogBoxParamW"},
        {"user32.dll","ShowWindow"}, {"user32.dll","UpdateWindow"}, {"user32.dll","DestroyWindow"},
        {"user32.dll","CloseWindow"}, {"user32.dll","SetWindowPos"}, {"user32.dll","MoveWindow"},
        {"user32.dll","SetWindowLongA"}, {"user32.dll","SetWindowLongW"},
        {"user32.dll","SetWindowLongPtrA"}, {"user32.dll","SetWindowLongPtrW"},
        {"user32.dll","GetWindowLongA"}, {"user32.dll","GetWindowLongW"},
        {"user32.dll","FindWindowA"}, {"user32.dll","FindWindowW"},
        {"user32.dll","FindWindowExA"}, {"user32.dll","FindWindowExW"},
        {"user32.dll","EnumWindows"}, {"user32.dll","EnumChildWindows"},
        {"user32.dll","GetWindow"}, {"user32.dll","GetForegroundWindow"}, {"user32.dll","SetForegroundWindow"},
        {"user32.dll","SendMessageA"}, {"user32.dll","SendMessageW"},
        {"user32.dll","PostMessageA"}, {"user32.dll","PostMessageW"},
        {"user32.dll","SendNotifyMessageA"}, {"user32.dll","SendNotifyMessageW"},
        {"user32.dll","PostThreadMessageA"}, {"user32.dll","PostThreadMessageW"},
        {"user32.dll","DispatchMessageA"}, {"user32.dll","DispatchMessageW"},
        {"user32.dll","SetWindowsHookExA"}, {"user32.dll","SetWindowsHookExW"},
        {"user32.dll","UnhookWindowsHookEx"}, {"user32.dll","CallNextHookEx"},
        {"user32.dll","SetWinEventHook"}, {"user32.dll","UnhookWinEvent"},
        {"user32.dll","GetMessageA"}, {"user32.dll","GetMessageW"},
        {"user32.dll","PeekMessageA"}, {"user32.dll","PeekMessageW"},
        {"user32.dll","TranslateMessage"},
        {"user32.dll","SetWindowSubclass"}, {"comctl32.dll","SetWindowSubclass"},
    };
    for (auto& api : winApis)
        apis.push_back({api[0], api[1], ApiCategory::WINDOW_OPERATION});

    // ===== 键盘记录 =====
    const char* keyApis[][2] = {
        {"user32.dll","SetWindowsHookExA"}, {"user32.dll","SetWindowsHookExW"},
        {"user32.dll","GetAsyncKeyState"}, {"user32.dll","GetKeyState"},
        {"user32.dll","GetKeyboardState"}, {"user32.dll","SetKeyboardState"},
        {"user32.dll","keybd_event"}, {"user32.dll","SendInput"},
        {"user32.dll","GetForegroundWindow"},
        {"user32.dll","GetWindowTextA"}, {"user32.dll","GetWindowTextW"},
        {"user32.dll","GetWindowThreadProcessId"},
        {"user32.dll","RegisterRawInputDevices"},
        {"user32.dll","GetRawInputData"}, {"user32.dll","GetRawInputBuffer"},
    };
    for (auto& api : keyApis)
        apis.push_back({api[0], api[1], ApiCategory::KEYLOGGER});

    // ===== 远程操作 =====
    const char* remApis[][2] = {
        {"kernel32.dll","VirtualAllocEx"}, {"kernel32.dll","VirtualFreeEx"}, {"kernel32.dll","VirtualProtectEx"},
        {"kernel32.dll","ReadProcessMemory"}, {"kernel32.dll","WriteProcessMemory"},
        {"ntdll.dll","NtReadVirtualMemory"}, {"ntdll.dll","NtWriteVirtualMemory"},
        {"kernel32.dll","CreateRemoteThread"}, {"kernel32.dll","CreateRemoteThreadEx"},
        {"ntdll.dll","NtCreateThreadEx"}, {"ntdll.dll","RtlCreateUserThread"},
        {"kernel32.dll","GetThreadContext"}, {"kernel32.dll","SetThreadContext"},
        {"ntdll.dll","NtGetContextThread"}, {"ntdll.dll","NtSetContextThread"},
        {"kernel32.dll","OpenProcess"}, {"kernel32.dll","OpenProcessToken"},
        {"advapi32.dll","OpenProcessToken"}, {"ntdll.dll","NtOpenProcess"},
        {"kernel32.dll","QueueUserAPC"}, {"ntdll.dll","NtQueueApcThread"},
        {"kernel32.dll","DuplicateHandle"}, {"ntdll.dll","NtDuplicateObject"},
    };
    for (auto& api : remApis)
        apis.push_back({api[0], api[1], ApiCategory::REMOTE_OPERATION});

    // ===== 截图 =====
    const char* scrApis[][2] = {
        {"user32.dll","GetDC"}, {"user32.dll","GetDCEx"}, {"user32.dll","GetWindowDC"},
        {"user32.dll","ReleaseDC"}, {"user32.dll","CreateDCW"}, {"user32.dll","CreateDCA"},
        {"gdi32.dll","BitBlt"}, {"gdi32.dll","StretchBlt"},
        {"gdi32.dll","CreateCompatibleDC"}, {"gdi32.dll","CreateCompatibleBitmap"},
        {"gdi32.dll","SelectObject"}, {"gdi32.dll","DeleteDC"}, {"gdi32.dll","DeleteObject"},
        {"gdi32.dll","GetDIBits"},
        {"d3d9.dll","CreateOffscreenPlainSurface"}, {"d3d9.dll","GetFrontBufferData"},
        {"user32.dll","SystemParametersInfoA"}, {"user32.dll","SystemParametersInfoW"},
        {"user32.dll","GetDesktopWindow"},
        {"user32.dll","PrintWindow"},
        {"dwmapi.dll","DwmGetDxSharedSurface"}, {"dwmapi.dll","DwmRegisterThumbnail"},
    };
    for (auto& api : scrApis)
        apis.push_back({api[0], api[1], ApiCategory::SCREENSHOT});

    // ===== 网络通信 =====
    const char* netApis[][2] = {
        {"ws2_32.dll","socket"}, {"ws2_32.dll","WSASocketA"}, {"ws2_32.dll","WSASocketW"},
        {"ws2_32.dll","accept"}, {"ws2_32.dll","WSAAccept"},
        {"ws2_32.dll","connect"}, {"ws2_32.dll","WSAConnect"},
        {"ws2_32.dll","bind"}, {"ws2_32.dll","listen"},
        {"ws2_32.dll","send"}, {"ws2_32.dll","sendto"}, {"ws2_32.dll","WSASend"}, {"ws2_32.dll","WSASendTo"},
        {"ws2_32.dll","recv"}, {"ws2_32.dll","recvfrom"}, {"ws2_32.dll","WSARecv"}, {"ws2_32.dll","WSARecvFrom"},
        {"ws2_32.dll","WSAStartup"}, {"ws2_32.dll","WSACleanup"},
        {"ws2_32.dll","closesocket"}, {"ws2_32.dll","shutdown"},
        {"ws2_32.dll","getsockname"}, {"ws2_32.dll","getpeername"},
        {"ws2_32.dll","setsockopt"}, {"ws2_32.dll","getsockopt"},
        {"ws2_32.dll","ioctlsocket"}, {"ws2_32.dll","select"},
        {"ws2_32.dll","gethostbyname"}, {"ws2_32.dll","gethostbyaddr"},
        {"ws2_32.dll","getaddrinfo"}, {"ws2_32.dll","freeaddrinfo"},
        {"winhttp.dll","WinHttpOpen"}, {"winhttp.dll","WinHttpConnect"},
        {"winhttp.dll","WinHttpOpenRequest"}, {"winhttp.dll","WinHttpSendRequest"},
        {"winhttp.dll","WinHttpReceiveResponse"}, {"winhttp.dll","WinHttpReadData"},
        {"winhttp.dll","WinHttpWriteData"}, {"winhttp.dll","WinHttpCloseHandle"},
        {"winhttp.dll","WinHttpSetStatusCallback"},
        {"wininet.dll","InternetOpenA"}, {"wininet.dll","InternetOpenW"},
        {"wininet.dll","InternetConnectA"}, {"wininet.dll","InternetConnectW"},
        {"wininet.dll","HttpOpenRequestA"}, {"wininet.dll","HttpOpenRequestW"},
        {"wininet.dll","HttpSendRequestA"}, {"wininet.dll","HttpSendRequestW"},
        {"wininet.dll","InternetReadFile"}, {"wininet.dll","InternetWriteFile"},
        {"wininet.dll","InternetCloseHandle"},
        {"wininet.dll","InternetSetStatusCallbackA"}, {"wininet.dll","InternetSetStatusCallbackW"},
        {"urlmon.dll","URLDownloadToFileA"}, {"urlmon.dll","URLDownloadToFileW"},
        {"dnsapi.dll","DnsQuery_A"}, {"dnsapi.dll","DnsQuery_W"},
        {"fwpuclnt.dll","FwpmEngineOpen"},
    };
    for (auto& api : netApis)
        apis.push_back({api[0], api[1], ApiCategory::NETWORK_COMMUNICATION});

    // ===== 注入 =====
    const char* injApis[][2] = {
        {"kernel32.dll","LoadLibraryA"}, {"kernel32.dll","LoadLibraryW"},
        {"kernel32.dll","LoadLibraryExA"}, {"kernel32.dll","LoadLibraryExW"},
        {"ntdll.dll","LdrLoadDll"},
        {"kernel32.dll","CreateRemoteThread"}, {"kernel32.dll","QueueUserAPC"},
        {"ntdll.dll","NtCreateThreadEx"}, {"ntdll.dll","RtlCreateUserThread"},
        {"ntdll.dll","NtMapViewOfSection"},
        {"kernel32.dll","VirtualAlloc"}, {"kernel32.dll","VirtualProtect"},
        {"kernel32.dll","WriteProcessMemory"},
        {"user32.dll","SetWindowsHookExA"}, {"user32.dll","SetWindowsHookExW"},
        {"ole32.dll","CoCreateInstance"}, {"ole32.dll","CoGetClassObject"},
        {"kernel32.dll","GetModuleHandleA"}, {"kernel32.dll","GetModuleHandleW"},
        {"kernel32.dll","GetProcAddress"},
    };
    for (auto& api : injApis)
        apis.push_back({api[0], api[1], ApiCategory::INJECTION});

    // ===== 反调试 =====
    const char* adApis[][2] = {
        {"kernel32.dll","IsDebuggerPresent"}, {"kernel32.dll","CheckRemoteDebuggerPresent"},
        {"ntdll.dll","NtQueryInformationProcess"}, {"ntdll.dll","NtSetInformationThread"},
        {"ntdll.dll","NtQuerySystemInformation"},
        {"kernel32.dll","DebugActiveProcess"}, {"kernel32.dll","DebugActiveProcessStop"},
        {"kernel32.dll","DebugBreak"},
        {"kernel32.dll","OutputDebugStringA"}, {"kernel32.dll","OutputDebugStringW"},
        {"kernel32.dll","GetTickCount"}, {"kernel32.dll","GetTickCount64"},
        {"kernel32.dll","QueryPerformanceCounter"},
        {"ntdll.dll","NtQueryPerformanceCounter"},
        {"kernel32.dll","SetUnhandledExceptionFilter"},
        {"kernel32.dll","UnhandledExceptionFilter"},
        {"kernel32.dll","RaiseException"},
        {"ntdll.dll","RtlDispatchException"},
        {"ntdll.dll","NtClose"},
        {"ntdll.dll","ZwSetInformationThread"},
    };
    for (auto& api : adApis)
        apis.push_back({api[0], api[1], ApiCategory::ANTI_DEBUG});

    // ===== 枚举 =====
    const char* enumApis[][2] = {
        {"kernel32.dll","CreateToolhelp32Snapshot"},
        {"kernel32.dll","Process32FirstW"}, {"kernel32.dll","Process32NextW"},
        {"psapi.dll","EnumProcesses"},
        {"kernel32.dll","Thread32First"}, {"kernel32.dll","Thread32Next"},
        {"kernel32.dll","Module32FirstW"}, {"kernel32.dll","Module32NextW"},
        {"psapi.dll","EnumProcessModules"}, {"psapi.dll","EnumProcessModulesEx"},
        {"user32.dll","EnumWindows"}, {"user32.dll","EnumChildWindows"},
        {"advapi32.dll","EnumServicesStatusA"}, {"advapi32.dll","EnumServicesStatusW"},
        {"advapi32.dll","EnumServicesStatusExA"}, {"advapi32.dll","EnumServicesStatusExW"},
        {"psapi.dll","EnumDeviceDrivers"},
        {"kernel32.dll","EnumResourceTypesA"}, {"kernel32.dll","EnumResourceTypesW"},
        {"kernel32.dll","EnumResourceNamesA"}, {"kernel32.dll","EnumResourceNamesW"},
    };
    for (auto& api : enumApis)
        apis.push_back({api[0], api[1], ApiCategory::ENUMERATION});

    // ===== 提权/系统信息 =====
    const char* privApis[][2] = {
        {"advapi32.dll","OpenProcessToken"}, {"advapi32.dll","OpenThreadToken"},
        {"advapi32.dll","AdjustTokenPrivileges"},
        {"advapi32.dll","LookupPrivilegeValueA"}, {"advapi32.dll","LookupPrivilegeValueW"},
        {"advapi32.dll","DuplicateToken"}, {"advapi32.dll","DuplicateTokenEx"},
        {"advapi32.dll","ImpersonateLoggedOnUser"},
        {"advapi32.dll","ImpersonateSelf"}, {"advapi32.dll","RevertToSelf"},
        {"kernel32.dll","GetSystemInfo"}, {"kernel32.dll","GetNativeSystemInfo"},
        {"kernel32.dll","GetVersion"}, {"kernel32.dll","GetVersionExA"}, {"kernel32.dll","GetVersionExW"},
        {"kernel32.dll","GetComputerNameA"}, {"kernel32.dll","GetComputerNameW"},
        {"kernel32.dll","GetUserNameA"}, {"kernel32.dll","GetUserNameW"},
        {"ntdll.dll","NtQuerySystemInformation"}, {"ntdll.dll","RtlGetVersion"},
        {"advapi32.dll","OpenSCManagerA"}, {"advapi32.dll","OpenSCManagerW"},
        {"advapi32.dll","CreateServiceA"}, {"advapi32.dll","CreateServiceW"},
        {"advapi32.dll","StartServiceA"}, {"advapi32.dll","StartServiceW"},
        {"advapi32.dll","ControlService"}, {"advapi32.dll","DeleteService"},
        {"advapi32.dll","QueryServiceStatus"}, {"advapi32.dll","QueryServiceConfigA"}, {"advapi32.dll","QueryServiceConfigW"},
    };
    for (auto& api : privApis)
        apis.push_back({api[0], api[1], ApiCategory::PRIVILEGE_SYSTEM});

    // ===== 同步 =====
    const char* syncApis[][2] = {
        {"kernel32.dll","CreateMutexA"}, {"kernel32.dll","CreateMutexW"},
        {"kernel32.dll","CreateMutexExA"}, {"kernel32.dll","CreateMutexExW"},
        {"kernel32.dll","OpenMutexA"}, {"kernel32.dll","OpenMutexW"},
        {"kernel32.dll","ReleaseMutex"},
        {"ntdll.dll","NtCreateMutant"}, {"ntdll.dll","NtOpenMutant"}, {"ntdll.dll","NtReleaseMutant"},
        {"kernel32.dll","CreateSemaphoreA"}, {"kernel32.dll","CreateSemaphoreW"},
        {"kernel32.dll","ReleaseSemaphore"},
        {"ntdll.dll","NtCreateSemaphore"}, {"ntdll.dll","NtOpenSemaphore"},
        {"kernel32.dll","CreateEventA"}, {"kernel32.dll","CreateEventW"},
        {"kernel32.dll","CreateEventExA"}, {"kernel32.dll","CreateEventExW"},
        {"kernel32.dll","OpenEventA"}, {"kernel32.dll","OpenEventW"},
        {"kernel32.dll","SetEvent"}, {"kernel32.dll","ResetEvent"}, {"kernel32.dll","PulseEvent"},
        {"ntdll.dll","NtCreateEvent"}, {"ntdll.dll","NtOpenEvent"},
        {"ntdll.dll","NtSetEvent"}, {"ntdll.dll","NtResetEvent"},
        {"kernel32.dll","InitializeCriticalSection"}, {"kernel32.dll","InitializeCriticalSectionAndSpinCount"},
        {"kernel32.dll","EnterCriticalSection"}, {"kernel32.dll","TryEnterCriticalSection"},
        {"kernel32.dll","LeaveCriticalSection"}, {"kernel32.dll","DeleteCriticalSection"},
        {"ntdll.dll","RtlInitializeCriticalSection"}, {"ntdll.dll","RtlEnterCriticalSection"},
        {"ntdll.dll","RtlLeaveCriticalSection"}, {"ntdll.dll","RtlDeleteCriticalSection"},
        {"kernel32.dll","InitializeSRWLock"},
        {"kernel32.dll","AcquireSRWLockExclusive"}, {"kernel32.dll","AcquireSRWLockShared"},
        {"kernel32.dll","ReleaseSRWLockExclusive"}, {"kernel32.dll","ReleaseSRWLockShared"},
        {"kernel32.dll","WaitForSingleObject"}, {"kernel32.dll","WaitForSingleObjectEx"},
        {"kernel32.dll","WaitForMultipleObjects"}, {"kernel32.dll","WaitForMultipleObjectsEx"},
        {"kernel32.dll","SignalObjectAndWait"},
        {"ntdll.dll","NtWaitForSingleObject"}, {"ntdll.dll","NtWaitForMultipleObjects"},
        {"kernel32.dll","InterlockedIncrement"}, {"kernel32.dll","InterlockedDecrement"},
        {"kernel32.dll","InterlockedExchange"}, {"kernel32.dll","InterlockedCompareExchange"},
        {"kernel32.dll","InitializeConditionVariable"},
        {"kernel32.dll","SleepConditionVariableCS"}, {"kernel32.dll","SleepConditionVariableSRW"},
        {"kernel32.dll","WakeConditionVariable"}, {"kernel32.dll","WakeAllConditionVariable"},
    };
    for (auto& api : syncApis)
        apis.push_back({api[0], api[1], ApiCategory::SYNCHRONIZATION});

    // ===== 完成端口 IOCP =====
    const char* iocpApis[][2] = {
        {"kernel32.dll","CreateIoCompletionPort"},
        {"kernel32.dll","GetQueuedCompletionStatus"}, {"kernel32.dll","GetQueuedCompletionStatusEx"},
        {"kernel32.dll","PostQueuedCompletionStatus"},
        {"ntdll.dll","NtCreateIoCompletion"}, {"ntdll.dll","NtSetIoCompletion"},
        {"ntdll.dll","NtRemoveIoCompletion"}, {"ntdll.dll","NtRemoveIoCompletionEx"},
        {"kernel32.dll","ReadFileEx"}, {"kernel32.dll","WriteFileEx"},
        {"kernel32.dll","CancelIo"}, {"kernel32.dll","CancelIoEx"},
        {"kernel32.dll","GetOverlappedResult"}, {"kernel32.dll","GetOverlappedResultEx"},
        {"ws2_32.dll","AcceptEx"}, {"ws2_32.dll","ConnectEx"},
        {"kernel32.dll","CreateNamedPipeA"}, {"kernel32.dll","CreateNamedPipeW"},
        {"kernel32.dll","ConnectNamedPipe"},
        {"kernel32.dll","CreateThreadpoolIo"}, {"kernel32.dll","StartThreadpoolIo"},
        {"kernel32.dll","CancelThreadpoolIo"}, {"kernel32.dll","CloseThreadpoolIo"},
    };
    for (auto& api : iocpApis)
        apis.push_back({api[0], api[1], ApiCategory::COMPLETION_PORT});

    // ===== 异常处理 =====
    const char* excApis[][2] = {
        {"kernel32.dll","SetUnhandledExceptionFilter"}, {"kernel32.dll","UnhandledExceptionFilter"},
        {"kernel32.dll","RaiseException"}, {"kernel32.dll","RaiseFailFastException"},
        {"ntdll.dll","NtRaiseException"}, {"ntdll.dll","RtlRaiseException"},
        {"kernel32.dll","AddVectoredExceptionHandler"}, {"kernel32.dll","AddVectoredContinueHandler"},
        {"kernel32.dll","RemoveVectoredExceptionHandler"}, {"kernel32.dll","RemoveVectoredContinueHandler"},
        {"ntdll.dll","RtlAddVectoredExceptionHandler"}, {"ntdll.dll","RtlRemoveVectoredExceptionHandler"},
        {"ntdll.dll","RtlDispatchException"}, {"ntdll.dll","KiUserExceptionDispatcher"},
        {"kernel32.dll","GetExceptionInformation"}, {"kernel32.dll","GetExceptionCode"},
        {"kernel32.dll","GetLastError"}, {"kernel32.dll","SetLastError"},
        {"kernel32.dll","FormatMessageA"}, {"kernel32.dll","FormatMessageW"},
        {"kernel32.dll","TerminateProcess"}, {"kernel32.dll","ExitProcess"},
        {"kernel32.dll","TerminateThread"}, {"kernel32.dll","ExitThread"},
    };
    for (auto& api : excApis)
        apis.push_back({api[0], api[1], ApiCategory::EXCEPTION_HANDLING});

    // ===== Shell执行 =====
    const char* shellApis[][2] = {
        {"shell32.dll","ShellExecuteA"}, {"shell32.dll","ShellExecuteW"},
        {"shell32.dll","ShellExecuteExA"}, {"shell32.dll","ShellExecuteExW"},
        {"kernel32.dll","WinExec"},
        {"kernel32.dll","CreateProcessA"}, {"kernel32.dll","CreateProcessW"},
        {"msi.dll","MsiInstallProductA"}, {"msi.dll","MsiInstallProductW"},
        {"urlmon.dll","URLDownloadToFileA"}, {"urlmon.dll","URLDownloadToFileW"},
        {"shell32.dll","FindExecutableA"}, {"shell32.dll","FindExecutableW"},
    };
    for (auto& api : shellApis)
        apis.push_back({api[0], api[1], ApiCategory::SHELL_EXECUTE});

    // ===== 加密 =====
    const char* cryptApis[][2] = {
        {"advapi32.dll","CryptAcquireContextA"}, {"advapi32.dll","CryptAcquireContextW"},
        {"advapi32.dll","CryptReleaseContext"},
        {"advapi32.dll","CryptGenKey"}, {"advapi32.dll","CryptImportKey"},
        {"advapi32.dll","CryptExportKey"}, {"advapi32.dll","CryptDestroyKey"},
        {"advapi32.dll","CryptEncrypt"}, {"advapi32.dll","CryptDecrypt"},
        {"advapi32.dll","CryptHashData"}, {"advapi32.dll","CryptCreateHash"}, {"advapi32.dll","CryptDestroyHash"},
        {"advapi32.dll","CryptSignHashA"}, {"advapi32.dll","CryptSignHashW"},
        {"advapi32.dll","CryptVerifySignatureA"}, {"advapi32.dll","CryptVerifySignatureW"},
        {"advapi32.dll","CryptGenRandom"},
        {"bcrypt.dll","BCryptOpenAlgorithmProvider"}, {"bcrypt.dll","BCryptCloseAlgorithmProvider"},
        {"bcrypt.dll","BCryptGenerateSymmetricKey"}, {"bcrypt.dll","BCryptGenerateKeyPair"},
        {"bcrypt.dll","BCryptEncrypt"}, {"bcrypt.dll","BCryptDecrypt"},
        {"bcrypt.dll","BCryptHashData"}, {"bcrypt.dll","BCryptCreateHash"}, {"bcrypt.dll","BCryptDestroyHash"},
        {"bcrypt.dll","BCryptGenRandom"},
        {"ncrypt.dll","NCryptOpenStorageProvider"}, {"ncrypt.dll","NCryptOpenKey"},
        {"ncrypt.dll","NCryptCreatePersistedKey"}, {"ncrypt.dll","NCryptDeleteKey"},
        {"ncrypt.dll","NCryptEncrypt"}, {"ncrypt.dll","NCryptDecrypt"},
        {"crypt32.dll","CertOpenStore"}, {"crypt32.dll","CertCloseStore"},
        {"crypt32.dll","CertFindCertificateInStore"},
        {"crypt32.dll","CryptProtectData"}, {"crypt32.dll","CryptUnprotectData"},
        {"crypt32.dll","CryptProtectMemory"}, {"crypt32.dll","CryptUnprotectMemory"},
        {"secur32.dll","InitializeSecurityContextA"}, {"secur32.dll","InitializeSecurityContextW"},
        {"secur32.dll","AcceptSecurityContext"}, {"secur32.dll","DeleteSecurityContext"},
        {"secur32.dll","EncryptMessage"}, {"secur32.dll","DecryptMessage"},
    };
    for (auto& api : cryptApis)
        apis.push_back({api[0], api[1], ApiCategory::CRYPTOGRAPHY});

    // ===== 随机数 =====
    const char* randApis[][2] = {
        {"advapi32.dll","CryptGenRandom"}, {"advapi32.dll","SystemFunction036"},
        {"bcrypt.dll","BCryptGenRandom"},
        {"ntdll.dll","RtlGenRandom"},
        {"ole32.dll","CoCreateGuid"},
        {"rpcrt4.dll","UuidCreate"}, {"rpcrt4.dll","UuidCreateSequential"},
        {"kernel32.dll","QueryPerformanceCounter"}, {"kernel32.dll","QueryPerformanceFrequency"},
        {"kernel32.dll","GetTickCount"}, {"kernel32.dll","GetTickCount64"},
    };
    for (auto& api : randApis)
        apis.push_back({api[0], api[1], ApiCategory::RANDOM_NUMBER});

    // ===== COM初始化 =====
    const char* comApis[][2] = {
        {"ole32.dll","CoInitialize"}, {"ole32.dll","CoInitializeEx"},
        {"ole32.dll","CoUninitialize"},
        {"ole32.dll","OleInitialize"}, {"ole32.dll","OleUninitialize"},
        {"ole32.dll","CoInitializeSecurity"},
        {"ole32.dll","CoCreateInstance"}, {"ole32.dll","CoCreateInstanceEx"},
        {"ole32.dll","CoGetClassObject"}, {"ole32.dll","CoGetObject"},
        {"ole32.dll","CoRegisterClassObject"}, {"ole32.dll","CoRevokeClassObject"},
        {"ole32.dll","DllRegisterServer"}, {"ole32.dll","DllUnregisterServer"},
        {"ole32.dll","DllGetClassObject"}, {"ole32.dll","DllCanUnloadNow"},
        {"ole32.dll","CoMarshalInterface"}, {"ole32.dll","CoUnmarshalInterface"},
        {"ole32.dll","SetErrorInfo"}, {"ole32.dll","GetErrorInfo"},
        {"ole32.dll","CoImpersonateClient"}, {"ole32.dll","CoRevertToSelf"},
        {"ole32.dll","CoSetProxyBlanket"},
        {"rpcrt4.dll","RpcBindingFromStringBindingA"}, {"rpcrt4.dll","RpcBindingFromStringBindingW"},
        {"rpcrt4.dll","NdrClientCall2"}, {"rpcrt4.dll","NdrServerCall2"},
    };
    for (auto& api : comApis)
        apis.push_back({api[0], api[1], ApiCategory::COM_INITIALIZATION});

    // ===== 横向移动 =====
    const char* lmApis[][2] = {
        {"netapi32.dll","NetShareAdd"}, {"netapi32.dll","NetShareDel"}, {"netapi32.dll","NetShareEnum"},
        {"netapi32.dll","NetUseAdd"}, {"netapi32.dll","NetUseDel"}, {"netapi32.dll","NetUseEnum"},
        {"mpr.dll","WNetAddConnection2A"}, {"mpr.dll","WNetAddConnection2W"},
        {"mpr.dll","WNetCancelConnection2A"}, {"mpr.dll","WNetCancelConnection2W"},
        {"advapi32.dll","OpenSCManagerA"}, {"advapi32.dll","OpenSCManagerW"},
        {"advapi32.dll","CreateServiceA"}, {"advapi32.dll","CreateServiceW"},
        {"advapi32.dll","StartServiceA"}, {"advapi32.dll","StartServiceW"},
        {"advapi32.dll","RegConnectRegistryA"}, {"advapi32.dll","RegConnectRegistryW"},
        {"advapi32.dll","LogonUserA"}, {"advapi32.dll","LogonUserW"},
        {"advapi32.dll","ImpersonateLoggedOnUser"},
        {"advapi32.dll","CreateProcessAsUserA"}, {"advapi32.dll","CreateProcessAsUserW"},
        {"kernel32.dll","CreateProcessWithTokenW"},
        {"wtsapi32.dll","WTSOpenServerA"}, {"wtsapi32.dll","WTSOpenServerW"},
        {"wtsapi32.dll","WTSEnumerateSessionsA"}, {"wtsapi32.dll","WTSEnumerateSessionsW"},
        {"kernel32.dll","CreateNamedPipeA"}, {"kernel32.dll","CreateNamedPipeW"},
        {"kernel32.dll","ConnectNamedPipe"}, {"kernel32.dll","CallNamedPipeA"}, {"kernel32.dll","CallNamedPipeW"},
    };
    for (auto& api : lmApis)
        apis.push_back({api[0], api[1], ApiCategory::LATERAL_MOVEMENT});

    // ===== 线程池 =====
    const char* tpApis[][2] = {
        {"kernel32.dll","CreateThreadpool"}, {"kernel32.dll","CloseThreadpool"},
        {"kernel32.dll","SetThreadpoolThreadMaximum"}, {"kernel32.dll","SetThreadpoolThreadMinimum"},
        {"kernel32.dll","CreateThreadpoolCleanupGroup"}, {"kernel32.dll","CloseThreadpoolCleanupGroup"},
        {"kernel32.dll","CreateThreadpoolWork"}, {"kernel32.dll","SubmitThreadpoolWork"},
        {"kernel32.dll","CloseThreadpoolWork"}, {"kernel32.dll","WaitForThreadpoolWorkCallbacks"},
        {"kernel32.dll","TrySubmitThreadpoolCallback"},
        {"kernel32.dll","CreateThreadpoolTimer"}, {"kernel32.dll","SetThreadpoolTimer"},
        {"kernel32.dll","CloseThreadpoolTimer"}, {"kernel32.dll","WaitForThreadpoolTimerCallbacks"},
        {"kernel32.dll","CreateThreadpoolWait"}, {"kernel32.dll","SetThreadpoolWait"},
        {"kernel32.dll","CloseThreadpoolWait"}, {"kernel32.dll","WaitForThreadpoolWaitCallbacks"},
        {"kernel32.dll","CreateThreadpoolIo"}, {"kernel32.dll","StartThreadpoolIo"},
        {"kernel32.dll","CancelThreadpoolIo"}, {"kernel32.dll","CloseThreadpoolIo"},
        {"kernel32.dll","WaitForThreadpoolIoCallbacks"},
        {"kernel32.dll","CreateJobObjectA"}, {"kernel32.dll","CreateJobObjectW"},
        {"kernel32.dll","AssignProcessToJobObject"}, {"kernel32.dll","TerminateJobObject"},
        {"ntdll.dll","TpAllocPool"}, {"ntdll.dll","TpReleasePool"},
        {"ntdll.dll","TpAllocWork"}, {"ntdll.dll","TpPostWork"}, {"ntdll.dll","TpReleaseWork"},
        {"ntdll.dll","TpAllocTimer"}, {"ntdll.dll","TpSetTimer"}, {"ntdll.dll","TpReleaseTimer"},
        {"ntdll.dll","TpAllocWait"}, {"ntdll.dll","TpSetWait"}, {"ntdll.dll","TpReleaseWait"},
        {"ntdll.dll","TpAllocIoCompletion"}, {"ntdll.dll","TpReleaseIoCompletion"},
    };
    for (auto& api : tpApis)
        apis.push_back({api[0], api[1], ApiCategory::THREAD_POOL});

    // ===== 回调执行 =====
    const char* cbApis[][2] = {
        {"kernel32.dll","CreateThread"},
        {"kernel32.dll","CreateThreadpoolWork"}, {"kernel32.dll","SubmitThreadpoolWork"},
        {"kernel32.dll","TrySubmitThreadpoolCallback"},
        {"kernel32.dll","CreateThreadpoolTimer"}, {"kernel32.dll","SetThreadpoolTimer"},
        {"kernel32.dll","CreateThreadpoolWait"}, {"kernel32.dll","SetThreadpoolWait"},
        {"kernel32.dll","CreateThreadpoolIo"}, {"kernel32.dll","StartThreadpoolIo"},
        {"kernel32.dll","QueueUserAPC"},
        {"user32.dll","SetWindowLongA"}, {"user32.dll","SetWindowLongW"},
        {"user32.dll","CallWindowProcA"}, {"user32.dll","CallWindowProcW"},
        {"user32.dll","SendMessageA"}, {"user32.dll","SendMessageW"},
        {"user32.dll","SendMessageCallbackA"}, {"user32.dll","SendMessageCallbackW"},
        {"user32.dll","SetTimer"},
        {"user32.dll","SetWindowsHookExA"}, {"user32.dll","SetWindowsHookExW"},
        {"user32.dll","SetWinEventHook"},
        {"user32.dll","EnumWindows"}, {"user32.dll","EnumChildWindows"},
        {"user32.dll","EnumDesktopWindows"}, {"user32.dll","EnumThreadWindows"},
        {"user32.dll","DialogBoxParamA"}, {"user32.dll","DialogBoxParamW"},
        {"kernel32.dll","EnumProcesses"}, {"psapi.dll","EnumProcessModules"},
        {"kernel32.dll","FindFirstFileA"}, {"kernel32.dll","FindFirstFileW"},
        {"advapi32.dll","RegEnumKeyExA"}, {"advapi32.dll","RegEnumKeyExW"},
        {"advapi32.dll","EnumServicesStatusA"}, {"advapi32.dll","EnumServicesStatusW"},
        {"kernel32.dll","AddVectoredExceptionHandler"},
        {"kernel32.dll","SetUnhandledExceptionFilter"},
        {"ntdll.dll","RtlDispatchException"},
        {"kernel32.dll","ReadDirectoryChangesW"},
        {"kernel32.dll","ReadFileEx"}, {"kernel32.dll","WriteFileEx"},
        {"winhttp.dll","WinHttpSetStatusCallback"},
        {"wininet.dll","InternetSetStatusCallbackA"}, {"wininet.dll","InternetSetStatusCallbackW"},
        {"advapi32.dll","RegisterServiceCtrlHandlerA"}, {"advapi32.dll","RegisterServiceCtrlHandlerW"},
        {"kernel32.dll","CreateFiber"}, {"kernel32.dll","CreateFiberEx"},
        {"kernel32.dll","ConvertThreadToFiber"}, {"kernel32.dll","SwitchToFiber"},
        {"ole32.dll","CoCreateInstance"}, {"ole32.dll","CoCreateInstanceEx"},
        {"oleaut32.dll","DispCallFunc"},
    };
    for (auto& api : cbApis)
        apis.push_back({api[0], api[1], ApiCategory::CALLBACK_EXECUTION});

    return apis;
}