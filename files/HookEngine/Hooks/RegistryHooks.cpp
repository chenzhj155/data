#include "RegistryHooks.h"
#include "../HookEngine.h"
#include <sstream>

// ========== 原始函数指针 ==========
static LSTATUS (WINAPI *Real_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY) = RegOpenKeyExW;
static LSTATUS (WINAPI *Real_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY) = RegOpenKeyExA;
static LSTATUS (WINAPI *Real_RegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD) = RegCreateKeyExW;
static LSTATUS (WINAPI *Real_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD) = RegSetValueExW;
static LSTATUS (WINAPI *Real_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD) = RegSetValueExA;
static LSTATUS (WINAPI *Real_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) = RegQueryValueExW;
static LSTATUS (WINAPI *Real_RegDeleteValueW)(HKEY, LPCWSTR) = RegDeleteValueW;
static LSTATUS (WINAPI *Real_RegDeleteKeyW)(HKEY, LPCWSTR) = RegDeleteKeyW;
static LSTATUS (WINAPI *Real_RegCloseKey)(HKEY) = RegCloseKey;
static LSTATUS (WINAPI *Real_RegEnumKeyExW)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME) = RegEnumKeyExW;
static LSTATUS (WINAPI *Real_RegEnumValueW)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD) = RegEnumValueW;
static LSTATUS (WINAPI *Real_RegConnectRegistryW)(LPCWSTR, HKEY, PHKEY) = RegConnectRegistryW;

// ========== 辅助函数 ==========
static std::string GetRootKeyName(HKEY hKey) {
    if (hKey == HKEY_LOCAL_MACHINE)  return "HKLM";
    if (hKey == HKEY_CURRENT_USER)   return "HKCU";
    if (hKey == HKEY_CLASSES_ROOT)   return "HKCR";
    if (hKey == HKEY_USERS)          return "HKU";
    if (hKey == HKEY_CURRENT_CONFIG) return "HKCC";
    return FmtHandle(hKey);
}

static std::string GetRegTypeName(DWORD type) {
    switch (type) {
        case REG_SZ:        return "REG_SZ";
        case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
        case REG_DWORD:     return "REG_DWORD";
        case REG_QWORD:     return "REG_QWORD";
        case REG_MULTI_SZ:  return "REG_MULTI_SZ";
        case REG_BINARY:    return "REG_BINARY";
        default:            return "TYPE_" + std::to_string(type);
    }
}

// ========== Hook 实现 ==========
LSTATUS WINAPI Hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    std::ostringstream params;
    params << "hKey=" << GetRootKeyName(hKey) << ", SubKey=" << FmtStrW(lpSubKey)
           << ", Access=" << FmtDWORD(samDesired);

    LSTATUS result = Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);

    std::ostringstream ret;
    ret << result << (result == ERROR_SUCCESS ? "(SUCCESS)" : "(FAILED)");
    if (result == ERROR_SUCCESS && phkResult) ret << " Key=" << FmtHandle(*phkResult);

    LOG_API_CALL("advapi32.dll", "RegOpenKeyExW", params.str(), ret.str(), ApiCategory::REGISTRY_OPERATION);
    return result;
}

LSTATUS WINAPI Hook_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType,
    const BYTE* lpData, DWORD cbData) {
    std::ostringstream params;
    params << "hKey=" << GetRootKeyName(hKey) << ", Name=" << FmtStrW(lpValueName)
           << ", Type=" << GetRegTypeName(dwType) << ", Size=" << cbData;

    if (lpData && cbData > 0 && cbData <= 4096) {
        params << ", Data=";
        if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
            params << FmtStrW((LPCWSTR)lpData);
        } else if (dwType == REG_DWORD && cbData >= 4) {
            params << FmtDWORD(*(DWORD*)lpData);
        } else if (dwType == REG_QWORD && cbData >= 8) {
            std::ostringstream oss;
            oss << "0x" << std::hex << *(DWORD64*)lpData;
            params << oss.str();
        } else {
            params << "[Binary:" << cbData << "bytes]";
        }
    }

    LSTATUS result = Real_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);

    std::string ret = std::to_string(result);
    ret += (result == ERROR_SUCCESS) ? "(SUCCESS)" : "(FAILED)";

    LOG_API_CALL("advapi32.dll", "RegSetValueExW", params.str(), ret, ApiCategory::REGISTRY_OPERATION);
    return result;
}

LSTATUS WINAPI Hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType,
    LPBYTE lpData, LPDWORD lpcbData) {
    std::ostringstream params;
    params << "hKey=" << GetRootKeyName(hKey) << ", Name=" << FmtStrW(lpValueName);

    LSTATUS result = Real_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    std::ostringstream ret;
    ret << result << (result == ERROR_SUCCESS ? "(SUCCESS)" : "(FAILED)");
    if (result == ERROR_SUCCESS && lpType) ret << " Type=" << GetRegTypeName(*lpType);
    if (result == ERROR_SUCCESS && lpcbData) ret << " Size=" << *lpcbData;

    LOG_API_CALL("advapi32.dll", "RegQueryValueExW", params.str(), ret.str(), ApiCategory::REGISTRY_OPERATION);
    return result;
}

LSTATUS WINAPI Hook_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName) {
    std::ostringstream params;
    params << "hKey=" << GetRootKeyName(hKey) << ", Name=" << FmtStrW(lpValueName);

    LSTATUS result = Real_RegDeleteValueW(hKey, lpValueName);

    std::string ret = std::to_string(result);
    ret += (result == ERROR_SUCCESS) ? "(SUCCESS)" : "(FAILED)";

    LOG_API_CALL("advapi32.dll", "RegDeleteValueW", params.str(), ret, ApiCategory::REGISTRY_OPERATION);
    return result;
}

LSTATUS WINAPI Hook_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey) {
    std::ostringstream params;
    params << "hKey=" << GetRootKeyName(hKey) << ", SubKey=" << FmtStrW(lpSubKey);

    LSTATUS result = Real_RegDeleteKeyW(hKey, lpSubKey);

    std::string ret = std::to_string(result);
    ret += (result == ERROR_SUCCESS) ? "(SUCCESS)" : "(FAILED)";

    LOG_API_CALL("advapi32.dll", "RegDeleteKeyW", params.str(), ret, ApiCategory::REGISTRY_OPERATION);
    return result;
}

LSTATUS WINAPI Hook_RegCloseKey(HKEY hKey) {
    std::string params = "hKey=" + FmtHandle(hKey);
    LSTATUS result = Real_RegCloseKey(hKey);
    LOG_API_CALL("advapi32.dll", "RegCloseKey", params, std::to_string(result), ApiCategory::REGISTRY_OPERATION);
    return result;
}

LSTATUS WINAPI Hook_RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName,
    LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime) {
    std::ostringstream params;
    params << "hKey=" << GetRootKeyName(hKey) << ", Index=" << dwIndex;

    LSTATUS result = Real_RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);

    std::ostringstream ret;
    ret << result;
    if (result == ERROR_SUCCESS && lpName) {
        std::wstring w(lpName);
        ret << " (Key:" << std::string(w.begin(), w.end()) << ")";
    }

    LOG_API_CALL("advapi32.dll", "RegEnumKeyExW", params.str(), ret.str(), ApiCategory::REGISTRY_OPERATION);
    return result;
}

LSTATUS WINAPI Hook_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSA, PHKEY phkResult, LPDWORD lpdwDisposition) {
    std::ostringstream params;
    params << "hKey=" << GetRootKeyName(hKey) << ", SubKey=" << FmtStrW(lpSubKey)
           << ", Access=" << FmtDWORD(samDesired);

    LSTATUS result = Real_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSA, phkResult, lpdwDisposition);

    std::ostringstream ret;
    ret << result;
    if (result == ERROR_SUCCESS && phkResult) ret << " (Key=" << FmtHandle(*phkResult) << ")";
    if (result == ERROR_SUCCESS && lpdwDisposition) {
        ret << (*lpdwDisposition == REG_CREATED_NEW_KEY ? " [CREATED]" : " [OPENED]");
    }

    LOG_API_CALL("advapi32.dll", "RegCreateKeyExW", params.str(), ret.str(), ApiCategory::REGISTRY_OPERATION);
    return result;
}

LSTATUS WINAPI Hook_RegConnectRegistryW(LPCWSTR lpMachineName, HKEY hKey, PHKEY phkResult) {
    std::ostringstream params;
    params << "Machine=" << FmtStrW(lpMachineName) << ", hKey=" << GetRootKeyName(hKey);

    LSTATUS result = Real_RegConnectRegistryW(lpMachineName, hKey, phkResult);

    std::ostringstream ret;
    ret << result;
    if (result == ERROR_SUCCESS && phkResult) ret << " (Key=" << FmtHandle(*phkResult) << ")";

    LOG_API_CALL("advapi32.dll", "RegConnectRegistryW", params.str(), ret.str(), ApiCategory::REGISTRY_OPERATION);
    return result;
}

void InstallRegistryHooks() {
    HOOK_API_ADVAPI32("RegOpenKeyExW", Hook_RegOpenKeyExW, Real_RegOpenKeyExW);
    HOOK_API_ADVAPI32("RegOpenKeyExA", Hook_RegOpenKeyExA, Real_RegOpenKeyExA);
    HOOK_API_ADVAPI32("RegCreateKeyExW", Hook_RegCreateKeyExW, Real_RegCreateKeyExW);
    HOOK_API_ADVAPI32("RegSetValueExW", Hook_RegSetValueExW, Real_RegSetValueExW);
    HOOK_API_ADVAPI32("RegSetValueExA", Hook_RegSetValueExA, Real_RegSetValueExA);
    HOOK_API_ADVAPI32("RegQueryValueExW", Hook_RegQueryValueExW, Real_RegQueryValueExW);
    HOOK_API_ADVAPI32("RegDeleteValueW", Hook_RegDeleteValueW, Real_RegDeleteValueW);
    HOOK_API_ADVAPI32("RegDeleteKeyW", Hook_RegDeleteKeyW, Real_RegDeleteKeyW);
    HOOK_API_ADVAPI32("RegCloseKey", Hook_RegCloseKey, Real_RegCloseKey);
    HOOK_API_ADVAPI32("RegEnumKeyExW", Hook_RegEnumKeyExW, Real_RegEnumKeyExW);
    HOOK_API_ADVAPI32("RegEnumValueW", Hook_RegEnumValueW, Real_RegEnumValueW);
    HOOK_API_ADVAPI32("RegConnectRegistryW", Hook_RegConnectRegistryW, Real_RegConnectRegistryW);
}