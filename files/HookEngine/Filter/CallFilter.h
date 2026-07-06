#pragma once

#include <windows.h>
#include <string>
#include <set>
#include <mutex>
#include <algorithm>

// ============================================
// 调用过滤器 - 过滤系统模块间的调用
// ============================================
class CallFilter {
public:
    static CallFilter& GetInstance();

    // 是否应该记录该模块的调用
    bool ShouldRecord(const std::string& moduleName);

    // 模块管理
    void AddExcludedModule(const std::string& module);
    void RemoveExcludedModule(const std::string& module);
    void AddIncludedModule(const std::string& module);

    // 配置
    void SetEnabled(bool enabled);
    void SetFilterSystemModules(bool filter);
    void ResetToDefaults();

    // 查询
    std::set<std::string> GetExcludedModules() const;
    std::set<std::string> GetIncludedModules() const;
    size_t GetExcludedCount() const;
    size_t GetIncludedCount() const;

private:
    CallFilter();
    CallFilter(const CallFilter&) = delete;
    CallFilter& operator=(const CallFilter&) = delete;

    bool IsSystemModule(const std::string& moduleName);

    mutable std::mutex m_mutex;
    std::set<std::string> m_excludedModules;
    std::set<std::string> m_includedModules;
    bool m_enabled = true;
    bool m_filterSystemModules = true;
};