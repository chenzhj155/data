#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>

// ============================================
// API类别枚举
// ============================================
enum class ApiCategory {
    FILE_OPERATION,
    REGISTRY_OPERATION,
    MEMORY_OPERATION,
    PROCESS_CREATION,
    THREAD_OPERATION,
    FIBER_OPERATION,
    WINDOW_OPERATION,
    KEYLOGGER,
    REMOTE_OPERATION,
    SCREENSHOT,
    NETWORK_COMMUNICATION,
    INJECTION,
    ANTI_DEBUG,
    ENUMERATION,
    PRIVILEGE_SYSTEM,
    SYNCHRONIZATION,
    COMPLETION_PORT,
    EXCEPTION_HANDLING,
    SHELL_EXECUTE,
    CRYPTOGRAPHY,
    RANDOM_NUMBER,
    COM_INITIALIZATION,
    LATERAL_MOVEMENT,
    THREAD_POOL,
    CALLBACK_EXECUTION
};

// 转换为字符串
inline const char* CategoryToString(ApiCategory cat) {
    switch (cat) {
        case ApiCategory::FILE_OPERATION:       return "File";
        case ApiCategory::REGISTRY_OPERATION:   return "Registry";
        case ApiCategory::MEMORY_OPERATION:     return "Memory";
        case ApiCategory::PROCESS_CREATION:     return "Process";
        case ApiCategory::THREAD_OPERATION:     return "Thread";
        case ApiCategory::FIBER_OPERATION:      return "Fiber";
        case ApiCategory::WINDOW_OPERATION:     return "Window";
        case ApiCategory::KEYLOGGER:            return "Keylogger";
        case ApiCategory::REMOTE_OPERATION:     return "Remote";
        case ApiCategory::SCREENSHOT:           return "Screenshot";
        case ApiCategory::NETWORK_COMMUNICATION:return "Network";
        case ApiCategory::INJECTION:            return "Injection";
        case ApiCategory::ANTI_DEBUG:           return "AntiDebug";
        case ApiCategory::ENUMERATION:          return "Enumeration";
        case ApiCategory::PRIVILEGE_SYSTEM:     return "Privilege";
        case ApiCategory::SYNCHRONIZATION:      return "Sync";
        case ApiCategory::COMPLETION_PORT:      return "IOCP";
        case ApiCategory::EXCEPTION_HANDLING:   return "Exception";
        case ApiCategory::SHELL_EXECUTE:        return "ShellExec";
        case ApiCategory::CRYPTOGRAPHY:         return "Crypto";
        case ApiCategory::RANDOM_NUMBER:        return "Random";
        case ApiCategory::COM_INITIALIZATION:   return "COM";
        case ApiCategory::LATERAL_MOVEMENT:     return "LateralMove";
        case ApiCategory::THREAD_POOL:          return "ThreadPool";
        case ApiCategory::CALLBACK_EXECUTION:   return "Callback";
        default: return "Unknown";
    }
}

// 单个API定义
struct ApiDef {
    std::string module;
    std::string name;
    ApiCategory category;
};

// 获取所有需要监控的API列表
std::vector<ApiDef> GetAllMonitoredApis();