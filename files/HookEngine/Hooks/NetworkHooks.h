#pragma once
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <wininet.h>

SOCKET WINAPI Hook_socket(int af, int type, int protocol);
int WINAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen);
int WINAPI Hook_bind(SOCKET s, const sockaddr* name, int namelen);
int WINAPI Hook_listen(SOCKET s, int backlog);
SOCKET WINAPI Hook_accept(SOCKET s, sockaddr* addr, int* addrlen);
int WINAPI Hook_send(SOCKET s, const char* buf, int len, int flags);
int WINAPI Hook_recv(SOCKET s, char* buf, int len, int flags);
int WINAPI Hook_WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
int WINAPI Hook_WSACleanup();
int WINAPI Hook_closesocket(SOCKET s);

HINTERNET WINAPI Hook_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
HINTERNET WINAPI Hook_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
HINTERNET WINAPI Hook_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR const* ppwszAcceptTypes, DWORD dwFlags);
BOOL WINAPI Hook_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
BOOL WINAPI Hook_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved);
BOOL WINAPI Hook_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL WINAPI Hook_WinHttpCloseHandle(HINTERNET hInternet);

HINTERNET WINAPI Hook_InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
HINTERNET WINAPI Hook_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUsername, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI Hook_InternetCloseHandle(HINTERNET hInternet);

HRESULT WINAPI Hook_URLDownloadToFileW(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);

void InstallNetworkHooks();