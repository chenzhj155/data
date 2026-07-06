#include "CallFilter.h"

CallFilter& CallFilter::GetInstance() {
    static CallFilter instance;
    return instance;
}

CallFilter::CallFilter() {
    // 默认排除系统模块
    const char* defaultExcluded[] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll",
        "user32.dll", "gdi32.dll", "gdi32full.dll", "win32u.dll",
        "ole32.dll", "oleaut32.dll", "shell32.dll", "shlwapi.dll",
        "comctl32.dll", "comdlg32.dll", "ws2_32.dll",
        "winhttp.dll", "wininet.dll", "crypt32.dll",
        "bcrypt.dll", "ncrypt.dll", "secur32.dll", "schannel.dll",
        "rpcrt4.dll", "msvcrt.dll", "ucrtbase.dll", "vcruntime.dll",
        "msvcp.dll", "imm32.dll", "version.dll", "uxtheme.dll",
        "dwmapi.dll", "setupapi.dll", "winmm.dll", "powrprof.dll",
        "propsys.dll", "bcryptprimitives.dll", "cryptbase.dll",
        "sspicli.dll", "cfgmgr32.dll", "devobj.dll", "wintrust.dll",
        "msasn1.dll", "cryptsp.dll", "wldp.dll", "ntmarta.dll",
        "profapi.dll", "kernel.appcore.dll", "windows.storage.dll",
        "clbcatq.dll", "dataexchange.dll", "dcomp.dll",
        "twinapi.appcore.dll", "twinapi.dll", "dxgi.dll", "d3d11.dll",
        "msctf.dll", "textinputframework.dll", "windowscodecs.dll",
        "apphelp.dll", "cryptnet.dll", "dnsapi.dll", "mswsock.dll",
        "nsi.dll", "iphlpapi.dll", "fwpuclnt.dll", "rasadhlp.dll",
        "winrnr.dll", "pnrpnsp.dll", "napinsp.dll",
    };

    for (const char* mod : defaultExcluded) {
        m_excludedModules.insert(mod);
    }
}

void CallFilter::AddExcludedModule(const std::string& module) {
    std::string lower = module;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_excludedModules.insert(lower);
}

void CallFilter::RemoveExcludedModule(const std::string& module) {
    std::string lower = module;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_excludedModules.erase(lower);
}

void CallFilter::AddIncludedModule(const std::string& module) {
    std::string lower = module;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    std::lock_guard<std::mutex> lock(m_mutex);
    m_includedModules.insert(lower);
}

bool CallFilter::ShouldRecord(const std::string& moduleName) {
    if (!m_enabled) return true;

    std::string lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::lock_guard<std::mutex> lock(m_mutex);

    // 白名单优先
    if (!m_includedModules.empty()) {
        return m_includedModules.count(lower) > 0;
    }

    // 检查黑名单
    if (m_excludedModules.count(lower) > 0) {
        return false;
    }

    // 检查系统模块
    if (m_filterSystemModules && IsSystemModule(lower)) {
        return false;
    }

    return true;
}

void CallFilter::SetEnabled(bool enabled) {
    m_enabled = enabled;
}

void CallFilter::SetFilterSystemModules(bool filter) {
    m_filterSystemModules = filter;
}

void CallFilter::ResetToDefaults() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_excludedModules.clear();
    m_includedModules.clear();
    // 重新添加默认排除项
    const char* defaultExcluded[] = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll",
        "user32.dll", "gdi32.dll", "gdi32full.dll", "win32u.dll",
        "ole32.dll", "oleaut32.dll", "shell32.dll", "ws2_32.dll",
        "crypt32.dll", "bcrypt.dll", "rpcrt4.dll",
        "msvcrt.dll", "ucrtbase.dll", "secur32.dll",
    };
    for (const char* mod : defaultExcluded) {
        m_excludedModules.insert(mod);
    }
}

std::set<std::string> CallFilter::GetExcludedModules() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_excludedModules;
}

std::set<std::string> CallFilter::GetIncludedModules() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_includedModules;
}

size_t CallFilter::GetExcludedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_excludedModules.size();
}

size_t CallFilter::GetIncludedCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_includedModules.size();
}

bool CallFilter::IsSystemModule(const std::string& moduleName) {
    static const std::set<std::string> sysModules = {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll",
        "user32.dll", "gdi32.dll", "gdi32full.dll", "win32u.dll",
        "ole32.dll", "oleaut32.dll", "shell32.dll", "shlwapi.dll",
        "comctl32.dll", "comdlg32.dll", "ws2_32.dll",
        "winhttp.dll", "wininet.dll", "crypt32.dll",
        "bcrypt.dll", "ncrypt.dll", "secur32.dll", "schannel.dll",
        "rpcrt4.dll", "msvcrt.dll", "ucrtbase.dll", "vcruntime.dll",
        "msvcp.dll", "imm32.dll", "version.dll", "uxtheme.dll",
        "dwmapi.dll", "setupapi.dll", "winmm.dll",
        "bcryptprimitives.dll", "cryptbase.dll", "sspicli.dll",
        "cfgmgr32.dll", "wintrust.dll", "msasn1.dll", "cryptsp.dll",
        "wldp.dll", "ntmarta.dll", "profapi.dll",
        "kernel.appcore.dll", "windows.storage.dll",
        "twinapi.appcore.dll", "dxgi.dll", "msctf.dll",
        "windowscodecs.dll", "dnsapi.dll", "mswsock.dll",
        "nsi.dll", "iphlpapi.dll", "fwpuclnt.dll",
    };

    return sysModules.count(moduleName) > 0;
}