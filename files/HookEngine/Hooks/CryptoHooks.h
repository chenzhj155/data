#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>

// CryptoAPI (传统)
BOOL WINAPI Hook_CryptAcquireContextW(HCRYPTPROV* phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags);
BOOL WINAPI Hook_CryptAcquireContextA(HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
BOOL WINAPI Hook_CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);
BOOL WINAPI Hook_CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL WINAPI Hook_CryptImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
BOOL WINAPI Hook_CryptExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
BOOL WINAPI Hook_CryptDestroyKey(HCRYPTKEY hKey);
BOOL WINAPI Hook_CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen);
BOOL WINAPI Hook_CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen);
BOOL WINAPI Hook_CryptHashData(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags);
BOOL WINAPI Hook_CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash);
BOOL WINAPI Hook_CryptDestroyHash(HCRYPTHASH hHash);
BOOL WINAPI Hook_CryptSignHashW(HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR szDescription, DWORD dwFlags, BYTE* pbSignature, DWORD* pdwSigLen);
BOOL WINAPI Hook_CryptVerifySignatureW(HCRYPTHASH hHash, const BYTE* pbSignature, DWORD dwSigLen, HCRYPTKEY hPubKey, LPCWSTR szDescription, DWORD dwFlags);
BOOL WINAPI Hook_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer);

// CNG API (下一代)
NTSTATUS WINAPI Hook_BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, DWORD dwFlags);
NTSTATUS WINAPI Hook_BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, DWORD dwFlags);
NTSTATUS WINAPI Hook_BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptGenerateKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey, ULONG dwLength, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptImportKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptExportKey(BCRYPT_KEY_HANDLE hKey, BCRYPT_KEY_HANDLE hExportKey, LPCWSTR pszBlobType, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);
NTSTATUS WINAPI Hook_BCryptEncrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE* phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash);
NTSTATUS WINAPI Hook_BCryptSignHash(BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptVerifySignature(BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags);
NTSTATUS WINAPI Hook_BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);

// NCrypt API (密钥存储)
SECURITY_STATUS WINAPI Hook_NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE* phProvider, LPCWSTR pszProviderName, DWORD dwFlags);
SECURITY_STATUS WINAPI Hook_NCryptOpenKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
SECURITY_STATUS WINAPI Hook_NCryptCreatePersistedKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE* phKey, LPCWSTR pszAlgId, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
SECURITY_STATUS WINAPI Hook_NCryptDeleteKey(NCRYPT_KEY_HANDLE hKey, DWORD dwFlags);
SECURITY_STATUS WINAPI Hook_NCryptEncrypt(NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID* pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI Hook_NCryptDecrypt(NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID* pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
SECURITY_STATUS WINAPI Hook_NCryptFreeObject(NCRYPT_HANDLE hObject);

// 数据保护 API (DPAPI)
BOOL WINAPI Hook_CryptProtectData(DATA_BLOB* pDataIn, LPCWSTR szDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut);
BOOL WINAPI Hook_CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut);

// 证书操作
HCERTSTORE WINAPI Hook_CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void* pvPara);
BOOL WINAPI Hook_CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
PCCERT_CONTEXT WINAPI Hook_CertFindCertificateInStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, const void* pvFindPara, PCCERT_CONTEXT pPrevCertContext);

// 安全通道 (SSL/TLS)
SECURITY_STATUS WINAPI Hook_InitializeSecurityContextW(PCredHandle phCredential, PCredHandle phContext, SEC_WCHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCredHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry);
SECURITY_STATUS WINAPI Hook_AcceptSecurityContext(PCredHandle phCredential, PCredHandle phContext, PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCredHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsTimeStamp);
SECURITY_STATUS WINAPI Hook_DeleteSecurityContext(PCredHandle phContext);
SECURITY_STATUS WINAPI Hook_EncryptMessage(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo);
SECURITY_STATUS WINAPI Hook_DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP);

void InstallCryptoHooks();