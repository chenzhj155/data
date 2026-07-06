#pragma once

#include <windows.h>
#include <MinHook.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <psapi.h>

#include "ApiRecord.h"
#include "ApiDatabase.h"
#include "Config.h"
#include "Filter/CallFilter.h"

// ============================================
// Hook 引擎核心
// ============================================
class HookEngine {
public:
    static HookEngine& GetInstance();

    bool Initialize(HMODULE hModule);
    void Shutdown();

    // 安装/卸载所有 Hook
    void InstallAllHooks();
    void UninstallAllHooks();

    // 获取调用者信息
    LPVOID GetCallerAddress();
    std::string GetCallerModuleName(LPVOID address);

    // 创建并提交 API 记录
    void LogApiCall(const std::string& module,
                    const std::string& api,
                    const std::string& params,
                    const std::string& retVal,
                    ApiCategory category);

    // 通用 Hook 创建
    template<typename T>
    bool CreateApiHook(const std::string& module,
                       const std::string& api,
                       LPVOID target,
                       LPVOID detour,
                       T* original) {
        MH_STATUS status = MH_CreateHook(target, detour, (LPVOID*)original);
        if (status != MH_OK) {
            char buf[256];
            sprintf_s(buf, "[ApiMonitor] Failed to create hook: %s!%s (err=%s)\n",
                     module.c_str(), api.c_str(), MH_StatusToString(status));
            OutputDebugStringA(buf);
            return false;
        }

        status = MH_EnableHook(target);
        if (status != MH_OK) {
            char buf[256];
            sprintf_s(buf, "[ApiMonitor] Failed to enable hook: %s!%s (err=%s)\n",
                     module.c_str(), api.c_str(), MH_StatusToString(status));
            OutputDebugStringA(buf);
            return false;
        }

        return true;
    }

    // 获取系统模块列表
    static bool IsSystemModule(const std::string& moduleName);

private:
    HookEngine() = default;
    ~HookEngine() { Shutdown(); }
    HookEngine(const HookEngine&) = delete;
    HookEngine& operator=(const HookEngine&) = delete;

    HMODULE m_module = nullptr;
    bool m_initialized = false;
    std::vector<std::pair<std::string, std::string>> m_installedHooks;
    std::mutex m_hookMutex;
    std::mutex m_logMutex;
};

// ============================================
// Hook 创建宏
// ============================================
#define HOOK_API_FULL(module, api, detour, original) \
    do { \
        HMODULE hMod = GetModuleHandleA(module); \
        if (!hMod) hMod = LoadLibraryA(module); \
        if (hMod) { \
            LPVOID target = GetProcAddress(hMod, api); \
            if (target) { \
                HookEngine::GetInstance().CreateApiHook(module, api, target, (LPVOID)detour, &original); \
            } \
        } \
    } while(0)

#define HOOK_API(api, detour, original) \
    HOOK_API_FULL("kernel32.dll", api, detour, original)

#define HOOK_API_ADVAPI32(api, detour, original) \
    HOOK_API_FULL("advapi32.dll", api, detour, original)

#define HOOK_API_USER32(api, detour, original) \
    HOOK_API_FULL("user32.dll", api, detour, original)

#define HOOK_API_WS2_32(api, detour, original) \
    HOOK_API_FULL("ws2_32.dll", api, detour, original)

#define HOOK_API_NTDLL(api, detour, original) \
    HOOK_API_FULL("ntdll.dll", api, detour, original)

#define HOOK_API_SHELL32(api, detour, original) \
    HOOK_API_FULL("shell32.dll", api, detour, original)

#define HOOK_API_CRYPT32(api, detour, original) \
    HOOK_API_FULL("crypt32.dll", api, detour, original)

#define HOOK_API_WINHTTP(api, detour, original) \
    HOOK_API_FULL("winhttp.dll", api, detour, original)

#define HOOK_API_WININET(api, detour, original) \
    HOOK_API_FULL("wininet.dll", api, detour, original)

#define HOOK_API_BCRYPT(api, detour, original) \
    HOOK_API_FULL("bcrypt.dll", api, detour, original)

#define HOOK_API_OLE32(api, detour, original) \
    HOOK_API_FULL("ole32.dll", api, detour, original)

#define HOOK_API_GDI32(api, detour, original) \
    HOOK_API_FULL("gdi32.dll", api, detour, original)

#define LOG_API_CALL(module, api, params, retVal, category) \
    HookEngine::GetInstance().LogApiCall(module, api, params, retVal, category)