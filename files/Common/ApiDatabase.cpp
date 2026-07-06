#include "ApiDatabase.h"
#include <iostream>

ApiDatabase& ApiDatabase::GetInstance() {
    static ApiDatabase instance;
    return instance;
}

void ApiDatabase::Initialize(const std::string& logPath, bool jsonFormat) {
    m_jsonFormat = jsonFormat;
    m_logFile.open(logPath, std::ios::out | std::ios::trunc);
    if (!m_logFile.is_open()) {
        OutputDebugStringA("[ApiMonitor] Failed to open log file\n");
        return;
    }
    m_running = true;
    m_worker = std::thread(&ApiDatabase::WriteLoop, this);

    // 默认排除系统模块间的调用
    AddExcludedCaller("ntdll.dll");
    AddExcludedCaller("kernel32.dll");
    AddExcludedCaller("kernelbase.dll");
    AddExcludedCaller("advapi32.dll");
    AddExcludedCaller("user32.dll");
    AddExcludedCaller("gdi32.dll");
    AddExcludedCaller("ole32.dll");
    AddExcludedCaller("shell32.dll");
    AddExcludedCaller("ws2_32.dll");
    AddExcludedCaller("crypt32.dll");
    AddExcludedCaller("bcrypt.dll");
    AddExcludedCaller("ncrypt.dll");
    AddExcludedCaller("msvcrt.dll");
    AddExcludedCaller("ucrtbase.dll");
    AddExcludedCaller("combase.dll");
    AddExcludedCaller("rpcrt4.dll");
    AddExcludedCaller("secur32.dll");
    AddExcludedCaller("schannel.dll");
    AddExcludedCaller("msasn1.dll");
    AddExcludedCaller("cryptsp.dll");
    AddExcludedCaller("wintrust.dll");
    AddExcludedCaller("bcryptprimitives.dll");
    AddExcludedCaller("sspicli.dll");
    AddExcludedCaller("cfgmgr32.dll");
    AddExcludedCaller("win32u.dll");
    AddExcludedCaller("gdi32full.dll");
}

void ApiDatabase::Shutdown() {
    m_running = false;
    m_cv.notify_all();
    if (m_worker.joinable()) m_worker.join();
    if (m_logFile.is_open()) m_logFile.close();
}

void ApiDatabase::AddRecord(const ApiCallRecord& record) {
    if (!m_enabled) return;
    if (!ShouldLog(record)) return;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(record);
        m_totalCalls++;
        m_callStats[record.apiName]++;
    }
    m_cv.notify_one();
}

void ApiDatabase::AddExcludedCaller(const std::string& module) {
    std::string lower = module;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_excludedCallers.insert(lower);
}

void ApiDatabase::SetEnabled(bool enabled) {
    m_enabled = enabled;
}

size_t ApiDatabase::GetTotalCalls() const {
    return m_totalCalls;
}

std::map<std::string, size_t> ApiDatabase::GetStatistics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_callStats;
}

bool ApiDatabase::ShouldLog(const ApiCallRecord& record) {
    std::string caller = record.callerModule;
    std::transform(caller.begin(), caller.end(), caller.begin(), ::tolower);

    std::lock_guard<std::mutex> lock(m_mutex);
    return m_excludedCallers.count(caller) == 0;
}

void ApiDatabase::WriteLoop() {
    while (m_running) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this] { return !m_queue.empty() || !m_running; });

        while (!m_queue.empty()) {
            auto record = m_queue.front();
            m_queue.pop();
            lock.unlock();

            if (m_logFile.is_open()) {
                if (m_jsonFormat)
                    m_logFile << record.SerializeJson() << std::endl;
                else
                    m_logFile << record.Serialize() << std::endl;
                m_logFile.flush();
            }

            lock.lock();
        }
    }
}