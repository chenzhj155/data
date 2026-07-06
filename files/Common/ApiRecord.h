#pragma once

#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <mutex>
#include <fstream>
#include <algorithm>

// ============================================
// API调用记录结构
// ============================================
struct ApiCallRecord {
    DWORD       processId;
    DWORD       threadId;
    std::string moduleName;      // 被调用的模块 (kernel32.dll, advapi32.dll...)
    std::string apiName;         // API名称
    std::string parameters;      // 参数
    std::string returnValue;     // 返回值
    DWORD64     callerAddress;   // 调用者地址
    std::string callerModule;    // 调用者模块名
    std::string category;        // API类别 (File, Registry, Network...)
    SYSTEMTIME  timestamp;       // 时间戳

    // 序列化为可读文本
    std::string Serialize() const {
        std::ostringstream oss;
        oss << std::setw(4) << timestamp.wYear << "-"
            << std::setw(2) << std::setfill('0') << timestamp.wMonth << "-"
            << std::setw(2) << std::setfill('0') << timestamp.wDay << " "
            << std::setw(2) << std::setfill('0') << timestamp.wHour << ":"
            << std::setw(2) << std::setfill('0') << timestamp.wMinute << ":"
            << std::setw(2) << std::setfill('0') << timestamp.wSecond << "."
            << std::setw(3) << std::setfill('0') << timestamp.wMilliseconds;

        return "[" + oss.str() + "]"
               " [PID:" + std::to_string(processId) +
               " TID:" + std::to_string(threadId) + "]"
               " [" + callerModule + "]"
               " [" + category + "]"
               " " + moduleName + "!" + apiName +
               "(" + parameters + ") -> " + returnValue;
    }

    // 序列化为JSON
    std::string SerializeJson() const {
        std::ostringstream oss;
        oss << "{"
            << "\"timestamp\":\"" << FormatTimestampISO() << "\","
            << "\"pid\":" << processId << ","
            << "\"tid\":" << threadId << ","
            << "\"caller\":\"" << EscapeJson(callerModule) << "\","
            << "\"category\":\"" << EscapeJson(category) << "\","
            << "\"module\":\"" << EscapeJson(moduleName) << "\","
            << "\"api\":\"" << EscapeJson(apiName) << "\","
            << "\"params\":\"" << EscapeJson(parameters) << "\","
            << "\"return\":\"" << EscapeJson(returnValue) << "\""
            << "}";
        return oss.str();
    }

    // 序列化为CSV
    std::string SerializeCsv() const {
        std::ostringstream oss;
        oss << FormatTimestampISO() << ","
            << processId << ","
            << threadId << ","
            << callerModule << ","
            << category << ","
            << moduleName << ","
            << apiName << ","
            << "\"" << parameters << "\","
            << "\"" << returnValue << "\"";
        return oss.str();
    }

private:
    std::string FormatTimestampISO() const {
        std::ostringstream oss;
        oss << std::setw(4) << timestamp.wYear << "-"
            << std::setw(2) << std::setfill('0') << timestamp.wMonth << "-"
            << std::setw(2) << std::setfill('0') << timestamp.wDay << "T"
            << std::setw(2) << std::setfill('0') << timestamp.wHour << ":"
            << std::setw(2) << std::setfill('0') << timestamp.wMinute << ":"
            << std::setw(2) << std::setfill('0') << timestamp.wSecond << "."
            << std::setw(3) << std::setfill('0') << timestamp.wMilliseconds;
        return oss.str();
    }

    std::string EscapeJson(const std::string& s) const {
        std::string r;
        for (char c : s) {
            switch (c) {
                case '"':  r += "\\\""; break;
                case '\\': r += "\\\\"; break;
                case '\n': r += "\\n";  break;
                case '\r': r += "\\r";  break;
                case '\t': r += "\\t";  break;
                default:   r += c;
            }
        }
        return r;
    }
};

// ============================================
// 格式化辅助函数
// ============================================
inline std::string FmtPtr(void* p) {
    if (!p) return "NULL";
    std::ostringstream oss;
    oss << "0x" << std::hex << (DWORD64)p;
    return oss.str();
}

inline std::string FmtHandle(HANDLE h) { return FmtPtr((void*)h); }

inline std::string FmtStrA(LPCSTR s) {
    if (!s) return "NULL";
    return "\"" + std::string(s) + "\"";
}

inline std::string FmtStrW(LPCWSTR s) {
    if (!s) return "NULL";
    int len = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "\"\"";
    std::string r(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, s, -1, &r[0], len, nullptr, nullptr);
    return "\"" + r + "\"";
}

inline std::string FmtDWORD(DWORD v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

inline std::string FmtBOOL(BOOL v) { return v ? "TRUE" : "FALSE"; }

inline std::string FmtSockAddr(const sockaddr* name, int namelen) {
    if (!name || namelen < (int)sizeof(sockaddr_in)) return "";
    const auto* addr = (const sockaddr_in*)name;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    std::ostringstream oss;
    oss << ip << ":" << ntohs(addr->sin_port);
    return oss.str();
}

inline std::string GetFileNameFromPath(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}