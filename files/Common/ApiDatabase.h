#pragma once

#include "ApiRecord.h"
#include <queue>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <set>

// ============================================
// API数据库 - 异步写入日志
// ============================================
class ApiDatabase {
public:
    static ApiDatabase& GetInstance();

    void Initialize(const std::string& logPath, bool jsonFormat = false);
    void Shutdown();
    void AddRecord(const ApiCallRecord& record);

    void AddExcludedCaller(const std::string& module);
    void SetEnabled(bool enabled);

    size_t GetTotalCalls() const;
    std::map<std::string, size_t> GetStatistics() const;

private:
    ApiDatabase() = default;
    ~ApiDatabase() { Shutdown(); }
    ApiDatabase(const ApiDatabase&) = delete;
    ApiDatabase& operator=(const ApiDatabase&) = delete;

    bool ShouldLog(const ApiCallRecord& record);
    void WriteLoop();

    std::ofstream m_logFile;
    std::queue<ApiCallRecord> m_queue;
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::thread m_worker;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_enabled{true};
    std::atomic<size_t> m_totalCalls{0};
    std::map<std::string, size_t> m_callStats;
    std::set<std::string> m_excludedCallers;
    bool m_jsonFormat = false;
};