#include "HookEngine.h"
#include "Hooks/AllHooks.h"
#include <iostream>
#include <set>

HookEngine& HookEngine::GetInstance() {
    static HookEngine instance;
    return instance;
}

bool HookEngine::Initialize(HMODULE hModule) {
    m_module = hModule;

    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        char buf[256];
        sprintf_s(buf, "[ApiMonitor] MinHook init failed: %s\n", MH_StatusToString(status));
        OutputDebugStringA(buf);
        return false;
    }

    m_initialized = true;
    OutputDebugStringA("[ApiMonitor] HookEngine initialized\n");
    return true;
}

void HookEngine::Shutdown() {
    if (!m_initialized) return;

    UninstallAllHooks();
    MH_Uninitialize();
    m_initialized = false;

    OutputDebugStringA("[ApiMonitor] HookEngine shutdown complete\n");
}

void HookEngine::InstallAllHooks() {
    if (!m_initialized) return;

    OutputDebugStringA("[ApiMonitor] Installing all hooks...\n");
    InstallAllApiHooks();

    std::lock_guard<std::mutex> lock(m_hookMutex);
    char buf[256];
    sprintf_s(buf, "[ApiMonitor] Total hooks installed: %zu\n", m_installedHooks.size());
    OutputDebugStringA(buf);
}

void HookEngine::UninstallAllHooks() {
    std::lock_guard<std::mutex> lock(m_hookMutex);
    MH_DisableHook(MH_ALL_HOOKS);
    MH_RemoveHook(MH_ALL_HOOKS);
    m_installedHooks.clear();
}

LPVOID HookEngine::GetCallerAddress() {
    LPVOID frames[5];
    WORD captured = RtlCaptureStackBackTrace(0, 5, frames, NULL);
    // frames[0] = RtlCaptureStackBackTrace
    // frames[1] = GetCallerAddress
    // frames[2] = Hook function
    // frames[3] = Actual caller
    // frames[4] = Caller's caller (if needed)
    return (captured >= 4) ? frames[3] : _ReturnAddress();
}

std::string HookEngine::GetCallerModuleName(LPVOID address) {
    if (!address) return "Unknown";

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        HMODULE hMod = (HMODULE)mbi.AllocationBase;
        char name[MAX_PATH];
        if (GetModuleFileNameA(hMod, name, MAX_PATH)) {
            std::string full(name);
            return GetFileNameFromPath(full);
        }
    }

    // 备用方法：枚举模块
    HANDLE hProcess = GetCurrentProcess();
    HMODULE modules[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, modules, sizeof(modules), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, modules[i], &modInfo, sizeof(modInfo))) {
                LPVOID base = modInfo.lpBaseOfDll;
                LPVOID end = (LPVOID)((DWORD64)base + modInfo.SizeOfImage);

                if (address >= base && address < end) {
                    char name[MAX_PATH];
                    GetModuleFileNameA(modules[i], name, MAX_PATH);
                    return GetFileNameFromPath(std::string(name));
                }
            }
        }
    }

    return "Unknown";
}

void HookEngine::LogApiCall(const std::string& module,
                            const std::string& api,
                            const std::string& params,
                            const std::string& retVal,
                            ApiCategory category) {
    LPVOID caller = GetCallerAddress();
    std::string callerModule = GetCallerModuleName(caller);

    // 检查过滤
    if (!CallFilter::GetInstance().ShouldRecord(callerModule)) {
        return;
    }

    ApiCallRecord record;
    record.processId = GetCurrentProcessId();
    record.threadId = GetCurrentThreadId();
    record.moduleName = module;
    record.apiName = api;
    record.parameters = params;
    record.returnValue = retVal;
    record.callerAddress = (DWORD64)caller;
    record.callerModule = callerModule;
    record.category = CategoryToString(category);
    GetLocalTime(&record.timestamp);

    ApiDatabase::GetInstance().AddRecord(record);
}

bool HookEngine::IsSystemModule(const std::string& moduleName) {
    static const std::set<std::string> sysModules = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll",
        "user32.dll", "gdi32.dll", "ole32.dll", "oleaut32.dll",
        "shell32.dll", "shlwapi.dll", "comctl32.dll", "comdlg32.dll",
        "ws2_32.dll", "winhttp.dll", "wininet.dll",
        "crypt32.dll", "bcrypt.dll", "ncrypt.dll",
        "secur32.dll", "schannel.dll", "rpcrt4.dll",
        "msvcrt.dll", "ucrtbase.dll", "vcruntime.dll", "msvcp.dll",
        "imm32.dll", "version.dll", "uxtheme.dll", "dwmapi.dll",
        "setupapi.dll", "winmm.dll", "powrprof.dll", "propsys.dll",
        "bcryptprimitives.dll", "cryptbase.dll", "sspicli.dll",
        "cfgmgr32.dll", "devobj.dll", "wintrust.dll", "msasn1.dll",
        "cryptsp.dll", "wldp.dll", "ntmarta.dll", "profapi.dll",
        "kernel.appcore.dll", "windows.storage.dll", "clbcatq.dll",
        "dataexchange.dll", "dcomp.dll", "twinapi.appcore.dll",
        "twinapi.dll", "dxgi.dll", "d3d11.dll", "gdi32full.dll",
        "win32u.dll", "msctf.dll", "textinputframework.dll",
        "windowscodecs.dll", "apphelp.dll",
    };

    std::string lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return sysModules.count(lower) > 0;
}