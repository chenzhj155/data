#include "CryptoHooks.h"
#include "../HookEngine.h"
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "secur32.lib")

// ========== CryptoAPI 原始函数指针 ==========
static BOOL (WINAPI *Real_CryptAcquireContextW)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD) = CryptAcquireContextW;
static BOOL (WINAPI *Real_CryptAcquireContextA)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD) = CryptAcquireContextA;
static BOOL (WINAPI *Real_CryptReleaseContext)(HCRYPTPROV, DWORD) = CryptReleaseContext;
static BOOL (WINAPI *Real_CryptGenKey)(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*) = CryptGenKey;
static BOOL (WINAPI *Real_CryptImportKey)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*) = CryptImportKey;
static BOOL (WINAPI *Real_CryptExportKey)(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*) = CryptExportKey;
static BOOL (WINAPI *Real_CryptDestroyKey)(HCRYPTKEY) = CryptDestroyKey;
static BOOL (WINAPI *Real_CryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD) = CryptEncrypt;
static BOOL (WINAPI *Real_CryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*) = CryptDecrypt;
static BOOL (WINAPI *Real_CryptHashData)(HCRYPTHASH, const BYTE*, DWORD, DWORD) = CryptHashData;
static BOOL (WINAPI *Real_CryptCreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*) = CryptCreateHash;
static BOOL (WINAPI *Real_CryptDestroyHash)(HCRYPTHASH) = CryptDestroyHash;
static BOOL (WINAPI *Real_CryptSignHashW)(HCRYPTHASH, DWORD, LPCWSTR, DWORD, BYTE*, DWORD*) = CryptSignHashW;
static BOOL (WINAPI *Real_CryptVerifySignatureW)(HCRYPTHASH, const BYTE*, DWORD, HCRYPTKEY, LPCWSTR, DWORD) = CryptVerifySignatureW;
static BOOL (WINAPI *Real_CryptGenRandom)(HCRYPTPROV, DWORD, BYTE*) = CryptGenRandom;

// ========== CNG API 原始函数指针 ==========
static NTSTATUS (WINAPI *Real_BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, DWORD) = BCryptOpenAlgorithmProvider;
static NTSTATUS (WINAPI *Real_BCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, DWORD) = BCryptCloseAlgorithmProvider;
static NTSTATUS (WINAPI *Real_BCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG) = BCryptGenerateSymmetricKey;
static NTSTATUS (WINAPI *Real_BCryptGenerateKeyPair)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, ULONG, ULONG) = BCryptGenerateKeyPair;
static NTSTATUS (WINAPI *Real_BCryptImportKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG) = BCryptImportKey;
static NTSTATUS (WINAPI *Real_BCryptExportKey)(BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG) = BCryptExportKey;
static NTSTATUS (WINAPI *Real_BCryptDestroyKey)(BCRYPT_KEY_HANDLE) = BCryptDestroyKey;
static NTSTATUS (WINAPI *Real_BCryptEncrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG) = BCryptEncrypt;
static NTSTATUS (WINAPI *Real_BCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG) = BCryptDecrypt;
static NTSTATUS (WINAPI *Real_BCryptHashData)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG) = BCryptHashData;
static NTSTATUS (WINAPI *Real_BCryptCreateHash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG) = BCryptCreateHash;
static NTSTATUS (WINAPI *Real_BCryptDestroyHash)(BCRYPT_HASH_HANDLE) = BCryptDestroyHash;
static NTSTATUS (WINAPI *Real_BCryptSignHash)(BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG) = BCryptSignHash;
static NTSTATUS (WINAPI *Real_BCryptVerifySignature)(BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG) = BCryptVerifySignature;
static NTSTATUS (WINAPI *Real_BCryptGenRandom)(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG) = BCryptGenRandom;

// ========== NCrypt API 原始函数指针 ==========
static SECURITY_STATUS (WINAPI *Real_NCryptOpenStorageProvider)(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD) = NCryptOpenStorageProvider;
static SECURITY_STATUS (WINAPI *Real_NCryptOpenKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD) = NCryptOpenKey;
static SECURITY_STATUS (WINAPI *Real_NCryptCreatePersistedKey)(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, LPCWSTR, DWORD, DWORD) = NCryptCreatePersistedKey;
static SECURITY_STATUS (WINAPI *Real_NCryptDeleteKey)(NCRYPT_KEY_HANDLE, DWORD) = NCryptDeleteKey;
static SECURITY_STATUS (WINAPI *Real_NCryptEncrypt)(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD) = NCryptEncrypt;
static SECURITY_STATUS (WINAPI *Real_NCryptDecrypt)(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD) = NCryptDecrypt;
static SECURITY_STATUS (WINAPI *Real_NCryptFreeObject)(NCRYPT_HANDLE) = NCryptFreeObject;

// ========== DPAPI 原始函数指针 ==========
static BOOL (WINAPI *Real_CryptProtectData)(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*) = CryptProtectData;
static BOOL (WINAPI *Real_CryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*) = CryptUnprotectData;

// ========== 证书操作原始函数指针 ==========
static HCERTSTORE (WINAPI *Real_CertOpenStore)(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*) = CertOpenStore;
static BOOL (WINAPI *Real_CertCloseStore)(HCERTSTORE, DWORD) = CertCloseStore;
static PCCERT_CONTEXT (WINAPI *Real_CertFindCertificateInStore)(HCERTSTORE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT) = CertFindCertificateInStore;

// ========== SSL/TLS 原始函数指针 ==========
static SECURITY_STATUS (WINAPI *Real_InitializeSecurityContextW)(PCredHandle, PCredHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCredHandle, PSecBufferDesc, PULONG, PTimeStamp) = InitializeSecurityContextW;
static SECURITY_STATUS (WINAPI *Real_AcceptSecurityContext)(PCredHandle, PCredHandle, PSecBufferDesc, ULONG, ULONG, PCredHandle, PSecBufferDesc, PULONG, PTimeStamp) = AcceptSecurityContext;
static SECURITY_STATUS (WINAPI *Real_DeleteSecurityContext)(PCredHandle) = DeleteSecurityContext;
static SECURITY_STATUS (WINAPI *Real_EncryptMessage)(PCtxtHandle, ULONG, PSecBufferDesc, ULONG) = EncryptMessage;
static SECURITY_STATUS (WINAPI *Real_DecryptMessage)(PCtxtHandle, PSecBufferDesc, ULONG, PULONG) = DecryptMessage;

// ========== 辅助函数 ==========
static std::string HexDump(const BYTE* data, DWORD len, DWORD maxShow = 32) {
    if (!data || len == 0) return "[]";
    std::ostringstream oss;
    oss << "[";
    DWORD show = min(len, maxShow);
    for (DWORD i = 0; i < show; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i < show - 1) oss << " ";
    }
    if (len > maxShow) oss << " ... (" << len << " bytes total)";
    oss << "]";
    return oss.str();
}

static std::string GetAlgorithmName(LPCWSTR algId) {
    if (!algId) return "NULL";
    std::wstring w(algId);
    std::string s(w.begin(), w.end());
    if (s == "AES") return "AES";
    if (s == "3DES") return "3DES";
    if (s == "RSA") return "RSA";
    if (s == "ECDSA") return "ECDSA";
    if (s == "ECDH") return "ECDH";
    if (s == "SHA1") return "SHA1";
    if (s == "SHA256") return "SHA256";
    if (s == "SHA512") return "SHA512";
    if (s == "MD5") return "MD5";
    return s;
}

// ========== Hook 实现 ==========

BOOL WINAPI Hook_CryptAcquireContextW(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags) {
    std::ostringstream params;
    params << "Container=" << FmtStrW(szContainer) << ", Provider=" << FmtStrW(szProvider)
           << ", ProvType=" << dwProvType << ", Flags=" << FmtDWORD(dwFlags);

    BOOL result = Real_CryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && phProv) ret << " (hProv=" << FmtPtr((void*)*phProv) << ")";
    if (!result) ret << " (Err:" << GetLastError() << ")";

    LOG_API_CALL("advapi32.dll", "CryptAcquireContextW", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

BOOL WINAPI Hook_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey) {
    std::ostringstream params;
    params << "hProv=" << FmtPtr((void*)hProv) << ", Algid=" << Algid
           << ", Flags=" << FmtDWORD(dwFlags);

    // 识别常见算法
    switch (Algid) {
        case CALG_RC4:    params << "(RC4)"; break;
        case CALG_RC2:    params << "(RC2)"; break;
        case CALG_3DES:   params << "(3DES)"; break;
        case CALG_AES_128: params << "(AES-128)"; break;
        case CALG_AES_256: params << "(AES-256)"; break;
        case CALG_RSA_KEYX: params << "(RSA-KEYX)"; break;
        case CALG_RSA_SIGN: params << "(RSA-SIGN)"; break;
    }
    if (dwFlags & CRYPT_EXPORTABLE) params << " [EXPORTABLE]";

    BOOL result = Real_CryptGenKey(hProv, Algid, dwFlags, phKey);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && phKey) ret << " (hKey=" << FmtPtr((void*)*phKey) << ")";

    LOG_API_CALL("advapi32.dll", "CryptGenKey", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

BOOL WINAPI Hook_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    std::ostringstream params;
    params << "hKey=" << FmtPtr((void*)hKey) << ", Final=" << FmtBOOL(Final)
           << ", DataLen=" << (pdwDataLen ? *pdwDataLen : 0)
           << ", BufLen=" << dwBufLen;

    if (pbData && pdwDataLen && *pdwDataLen > 0 && *pdwDataLen <= 256) {
        params << ", Before=" << HexDump(pbData, *pdwDataLen, 16);
    }

    BOOL result = Real_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && pdwDataLen) {
        ret << " (EncryptedLen:" << *pdwDataLen << ")";
        if (pbData && *pdwDataLen > 0 && *pdwDataLen <= 256) {
            ret << " After=" << HexDump(pbData, *pdwDataLen, 16);
        }
    }

    LOG_API_CALL("advapi32.dll", "CryptEncrypt", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

BOOL WINAPI Hook_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
    std::ostringstream params;
    params << "hKey=" << FmtPtr((void*)hKey) << ", Final=" << FmtBOOL(Final)
           << ", DataLen=" << (pdwDataLen ? *pdwDataLen : 0);

    BOOL result = Real_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && pdwDataLen) ret << " (DecryptedLen:" << *pdwDataLen << ")";

    LOG_API_CALL("advapi32.dll", "CryptDecrypt", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

BOOL WINAPI Hook_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer) {
    std::ostringstream params;
    params << "hProv=" << FmtPtr((void*)hProv) << ", Len=" << dwLen;

    BOOL result = Real_CryptGenRandom(hProv, dwLen, pbBuffer);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && pbBuffer && dwLen > 0) {
        ret << " Random=" << HexDump(pbBuffer, min(dwLen, 16u), 16);
    }

    LOG_API_CALL("advapi32.dll", "CryptGenRandom", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

NTSTATUS WINAPI Hook_BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, DWORD dwFlags) {
    std::ostringstream params;
    params << "AlgId=" << GetAlgorithmName(pszAlgId) << "(" << FmtStrW(pszAlgId) << ")"
           << ", Impl=" << FmtStrW(pszImplementation)
           << ", Flags=" << FmtDWORD(dwFlags);

    NTSTATUS result = Real_BCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, pszImplementation, dwFlags);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;
    if (result == 0 && phAlgorithm) ret << " (hAlg=" << FmtPtr(*phAlgorithm) << ")";

    LOG_API_CALL("bcrypt.dll", "BCryptOpenAlgorithmProvider", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

NTSTATUS WINAPI Hook_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    std::ostringstream params;
    params << "hKey=" << FmtPtr(hKey) << ", InputLen=" << cbInput
           << ", OutputLen=" << cbOutput << ", Flags=" << dwFlags;
    if (pbIV && cbIV > 0) params << ", IV=" << HexDump(pbIV, min(cbIV, 16u), 16);

    NTSTATUS result = Real_BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;
    if (result == 0 && pcbResult) ret << " (ResultLen:" << *pcbResult << ")";

    LOG_API_CALL("bcrypt.dll", "BCryptEncrypt", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

NTSTATUS WINAPI Hook_BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
    std::ostringstream params;
    params << "hKey=" << FmtPtr(hKey) << ", InputLen=" << cbInput
           << ", OutputLen=" << cbOutput;

    NTSTATUS result = Real_BCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;
    if (result == 0 && pcbResult) ret << " (ResultLen:" << *pcbResult << ")";

    LOG_API_CALL("bcrypt.dll", "BCryptDecrypt", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

NTSTATUS WINAPI Hook_BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags) {
    std::ostringstream params;
    params << "hAlg=" << FmtPtr(hAlgorithm) << ", Len=" << cbBuffer;

    NTSTATUS result = Real_BCryptGenRandom(hAlgorithm, pbBuffer, cbBuffer, dwFlags);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;

    LOG_API_CALL("bcrypt.dll", "BCryptGenRandom", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

SECURITY_STATUS WINAPI Hook_NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE* phProvider, LPCWSTR pszProviderName, DWORD dwFlags) {
    std::ostringstream params;
    params << "Provider=" << FmtStrW(pszProviderName) << ", Flags=" << FmtDWORD(dwFlags);

    SECURITY_STATUS result = Real_NCryptOpenStorageProvider(phProvider, pszProviderName, dwFlags);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;
    if (result == ERROR_SUCCESS && phProvider) ret << " (hProv=" << FmtPtr(*phProvider) << ")";

    LOG_API_CALL("ncrypt.dll", "NCryptOpenStorageProvider", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

SECURITY_STATUS WINAPI Hook_NCryptEncrypt(NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID* pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags) {
    std::ostringstream params;
    params << "hKey=" << FmtPtr(hKey) << ", InputLen=" << cbInput
           << ", OutputLen=" << cbOutput;

    SECURITY_STATUS result = Real_NCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;
    if (result == ERROR_SUCCESS && pcbResult) ret << " (ResultLen:" << *pcbResult << ")";

    LOG_API_CALL("ncrypt.dll", "NCryptEncrypt", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

BOOL WINAPI Hook_CryptProtectData(DATA_BLOB* pDataIn, LPCWSTR szDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) {
    std::ostringstream params;
    if (pDataIn) params << "DataLen=" << pDataIn->cbData;
    if (szDataDescr) params << ", Desc=" << FmtStrW(szDataDescr);
    params << ", Flags=" << FmtDWORD(dwFlags);
    if (dwFlags & CRYPTPROTECT_LOCAL_MACHINE) params << " [LOCAL_MACHINE]";

    BOOL result = Real_CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && pDataOut) ret << " (EncryptedLen:" << pDataOut->cbData << ")";

    LOG_API_CALL("crypt32.dll", "CryptProtectData", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

BOOL WINAPI Hook_CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) {
    std::ostringstream params;
    if (pDataIn) params << "DataLen=" << pDataIn->cbData;
    params << ", Flags=" << FmtDWORD(dwFlags);

    BOOL result = Real_CryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);

    std::ostringstream ret;
    ret << FmtBOOL(result);
    if (result && pDataOut) ret << " (DecryptedLen:" << pDataOut->cbData << ")";

    LOG_API_CALL("crypt32.dll", "CryptUnprotectData", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

SECURITY_STATUS WINAPI Hook_InitializeSecurityContextW(PCredHandle phCredential, PCredHandle phContext, SEC_WCHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCredHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry) {
    std::ostringstream params;
    params << "Target=" << FmtStrW(pszTargetName) << ", ContextReq=0x" << std::hex << fContextReq;

    SECURITY_STATUS result = Real_InitializeSecurityContextW(phCredential, phContext, pszTargetName, fContextReq, Reserved1, TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;
    if (result == SEC_E_OK) ret << " (SUCCESS)";
    else if (result == SEC_I_CONTINUE_NEEDED) ret << " (CONTINUE_NEEDED)";

    LOG_API_CALL("secur32.dll", "InitializeSecurityContextW", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

SECURITY_STATUS WINAPI Hook_EncryptMessage(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo) {
    std::ostringstream params;
    params << "fQOP=" << fQOP << ", SeqNo=" << MessageSeqNo;

    SECURITY_STATUS result = Real_EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;

    LOG_API_CALL("secur32.dll", "EncryptMessage", params.str(), ret.str(), ApiCategory::CRYPTOGRAPHY);
    return result;
}

void InstallCryptoHooks() {
    // CryptoAPI
    HOOK_API_ADVAPI32("CryptAcquireContextW", Hook_CryptAcquireContextW, Real_CryptAcquireContextW);
    HOOK_API_ADVAPI32("CryptAcquireContextA", Hook_CryptAcquireContextA, Real_CryptAcquireContextA);
    HOOK_API_ADVAPI32("CryptReleaseContext", Hook_CryptReleaseContext, Real_CryptReleaseContext);
    HOOK_API_ADVAPI32("CryptGenKey", Hook_CryptGenKey, Real_CryptGenKey);
    HOOK_API_ADVAPI32("CryptImportKey", Hook_CryptImportKey, Real_CryptImportKey);
    HOOK_API_ADVAPI32("CryptExportKey", Hook_CryptExportKey, Real_CryptExportKey);
    HOOK_API_ADVAPI32("CryptDestroyKey", Hook_CryptDestroyKey, Real_CryptDestroyKey);
    HOOK_API_ADVAPI32("CryptEncrypt", Hook_CryptEncrypt, Real_CryptEncrypt);
    HOOK_API_ADVAPI32("CryptDecrypt", Hook_CryptDecrypt, Real_CryptDecrypt);
    HOOK_API_ADVAPI32("CryptHashData", Hook_CryptHashData, Real_CryptHashData);
    HOOK_API_ADVAPI32("CryptCreateHash", Hook_CryptCreateHash, Real_CryptCreateHash);
    HOOK_API_ADVAPI32("CryptDestroyHash", Hook_CryptDestroyHash, Real_CryptDestroyHash);
    HOOK_API_ADVAPI32("CryptSignHashW", Hook_CryptSignHashW, Real_CryptSignHashW);
    HOOK_API_ADVAPI32("CryptVerifySignatureW", Hook_CryptVerifySignatureW, Real_CryptVerifySignatureW);
    HOOK_API_ADVAPI32("CryptGenRandom", Hook_CryptGenRandom, Real_CryptGenRandom);

    // CNG API
    HOOK_API_BCRYPT("BCryptOpenAlgorithmProvider", Hook_BCryptOpenAlgorithmProvider, Real_BCryptOpenAlgorithmProvider);
    HOOK_API_BCRYPT("BCryptCloseAlgorithmProvider", Hook_BCryptCloseAlgorithmProvider, Real_BCryptCloseAlgorithmProvider);
    HOOK_API_BCRYPT("BCryptGenerateSymmetricKey", Hook_BCryptGenerateSymmetricKey, Real_BCryptGenerateSymmetricKey);
    HOOK_API_BCRYPT("BCryptGenerateKeyPair", Hook_BCryptGenerateKeyPair, Real_BCryptGenerateKeyPair);
    HOOK_API_BCRYPT("BCryptImportKey", Hook_BCryptImportKey, Real_BCryptImportKey);
    HOOK_API_BCRYPT("BCryptExportKey", Hook_BCryptExportKey, Real_BCryptExportKey);
    HOOK_API_BCRYPT("BCryptDestroyKey", Hook_BCryptDestroyKey, Real_BCryptDestroyKey);
    HOOK_API_BCRYPT("BCryptEncrypt", Hook_BCryptEncrypt, Real_BCryptEncrypt);
    HOOK_API_BCRYPT("BCryptDecrypt", Hook_BCryptDecrypt, Real_BCryptDecrypt);
    HOOK_API_BCRYPT("BCryptHashData", Hook_BCryptHashData, Real_BCryptHashData);
    HOOK_API_BCRYPT("BCryptCreateHash", Hook_BCryptCreateHash, Real_BCryptCreateHash);
    HOOK_API_BCRYPT("BCryptDestroyHash", Hook_BCryptDestroyHash, Real_BCryptDestroyHash);
    HOOK_API_BCRYPT("BCryptSignHash", Hook_BCryptSignHash, Real_BCryptSignHash);
    HOOK_API_BCRYPT("BCryptVerifySignature", Hook_BCryptVerifySignature, Real_BCryptVerifySignature);
    HOOK_API_BCRYPT("BCryptGenRandom", Hook_BCryptGenRandom, Real_BCryptGenRandom);

    // NCrypt API
    HOOK_API_FULL("ncrypt.dll", "NCryptOpenStorageProvider", Hook_NCryptOpenStorageProvider, Real_NCryptOpenStorageProvider);
    HOOK_API_FULL("ncrypt.dll", "NCryptOpenKey", Hook_NCryptOpenKey, Real_NCryptOpenKey);
    HOOK_API_FULL("ncrypt.dll", "NCryptCreatePersistedKey", Hook_NCryptCreatePersistedKey, Real_NCryptCreatePersistedKey);
    HOOK_API_FULL("ncrypt.dll", "NCryptDeleteKey", Hook_NCryptDeleteKey, Real_NCryptDeleteKey);
    HOOK_API_FULL("ncrypt.dll", "NCryptEncrypt", Hook_NCryptEncrypt, Real_NCryptEncrypt);
    HOOK_API_FULL("ncrypt.dll", "NCryptDecrypt", Hook_NCryptDecrypt, Real_NCryptDecrypt);
    HOOK_API_FULL("ncrypt.dll", "NCryptFreeObject", Hook_NCryptFreeObject, Real_NCryptFreeObject);

    // DPAPI
    HOOK_API_CRYPT32("CryptProtectData", Hook_CryptProtectData, Real_CryptProtectData);
    HOOK_API_CRYPT32("CryptUnprotectData", Hook_CryptUnprotectData, Real_CryptUnprotectData);

    // 证书
    HOOK_API_CRYPT32("CertOpenStore", Hook_CertOpenStore, Real_CertOpenStore);
    HOOK_API_CRYPT32("CertCloseStore", Hook_CertCloseStore, Real_CertCloseStore);
    HOOK_API_CRYPT32("CertFindCertificateInStore", Hook_CertFindCertificateInStore, Real_CertFindCertificateInStore);

    // SSL/TLS
    HOOK_API_FULL("secur32.dll", "InitializeSecurityContextW", Hook_InitializeSecurityContextW, Real_InitializeSecurityContextW);
    HOOK_API_FULL("secur32.dll", "AcceptSecurityContext", Hook_AcceptSecurityContext, Real_AcceptSecurityContext);
    HOOK_API_FULL("secur32.dll", "DeleteSecurityContext", Hook_DeleteSecurityContext, Real_DeleteSecurityContext);
    HOOK_API_FULL("secur32.dll", "EncryptMessage", Hook_EncryptMessage, Real_EncryptMessage);
    HOOK_API_FULL("secur32.dll", "DecryptMessage", Hook_DecryptMessage, Real_DecryptMessage);
}