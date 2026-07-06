#include "NetworkHooks.h"
#include "../HookEngine.h"
#include <sstream>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")

// Socket
static SOCKET (WINAPI *Real_socket)(int, int, int) = socket;
static int (WINAPI *Real_connect)(SOCKET, const sockaddr*, int) = connect;
static int (WINAPI *Real_bind)(SOCKET, const sockaddr*, int) = bind;
static int (WINAPI *Real_listen)(SOCKET, int) = listen;
static SOCKET (WINAPI *Real_accept)(SOCKET, sockaddr*, int*) = accept;
static int (WINAPI *Real_send)(SOCKET, const char*, int, int) = send;
static int (WINAPI *Real_recv)(SOCKET, char*, int, int) = recv;
static int (WINAPI *Real_WSAStartup)(WORD, LPWSADATA) = WSAStartup;
static int (WINAPI *Real_WSACleanup)() = WSACleanup;
static int (WINAPI *Real_closesocket)(SOCKET) = closesocket;

// WinHTTP
static HINTERNET (WINAPI *Real_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = WinHttpOpen;
static HINTERNET (WINAPI *Real_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) = WinHttpConnect;
static HINTERNET (WINAPI *Real_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR const*, DWORD) = WinHttpOpenRequest;
static BOOL (WINAPI *Real_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) = WinHttpSendRequest;
static BOOL (WINAPI *Real_WinHttpReceiveResponse)(HINTERNET, LPVOID) = WinHttpReceiveResponse;
static BOOL (WINAPI *Real_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD) = WinHttpReadData;
static BOOL (WINAPI *Real_WinHttpCloseHandle)(HINTERNET) = WinHttpCloseHandle;

// WinINet
static HINTERNET (WINAPI *Real_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD) = InternetOpenA;
static HINTERNET (WINAPI *Real_InternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) = InternetConnectA;
static BOOL (WINAPI *Real_InternetCloseHandle)(HINTERNET) = InternetCloseHandle;

// URL
static HRESULT (WINAPI *Real_URLDownloadToFileW)(LPUNKNOWN, LPCWSTR, LPCWSTR, DWORD, LPBINDSTATUSCALLBACK) = URLDownloadToFileW;

// ========== Hook 实现 ==========
SOCKET WINAPI Hook_socket(int af, int type, int protocol) {
    std::ostringstream params;
    params << "af=" << af << ", type=" << type << ", protocol=" << protocol;

    SOCKET result = Real_socket(af, type, protocol);

    std::ostringstream ret;
    ret << result;
    if (result == INVALID_SOCKET) ret << " (Err:" << WSAGetLastError() << ")";

    LOG_API_CALL("ws2_32.dll", "socket", params.str(), ret.str(), ApiCategory::NETWORK_COMMUNICATION);
    return result;
}

int WINAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen) {
    std::ostringstream params;
    params << "s=" << s;
    std::string addr = FmtSockAddr(name, namelen);
    if (!addr.empty()) params << ", " << addr;

    int result = Real_connect(s, name, namelen);

    std::ostringstream ret;
    ret << result;
    if (result == SOCKET_ERROR) ret << " (Err:" << WSAGetLastError() << ")";

    LOG_API_CALL("ws2_32.dll", "connect", params.str(), ret.str(), ApiCategory::NETWORK_COMMUNICATION);
    return result;
}

int WINAPI Hook_send(SOCKET s, const char* buf, int len, int flags) {
    std::ostringstream params;
    params << "s=" << s << ", len=" << len;
    if (buf && len > 0 && len <= 256) {
        params << ", Data=[";
        for (int i = 0; i < min(len, 32); i++)
            params << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)buf[i] << " ";
        if (len > 32) params << "...";
        params << "]";
    }

    int result = Real_send(s, buf, len, flags);

    std::ostringstream ret;
    ret << result << " bytes";
    if (result == SOCKET_ERROR) ret << " (Err:" << WSAGetLastError() << ")";

    LOG_API_CALL("ws2_32.dll", "send", params.str(), ret.str(), ApiCategory::NETWORK_COMMUNICATION);
    return result;
}

int WINAPI Hook_recv(SOCKET s, char* buf, int len, int flags) {
    std::ostringstream params;
    params << "s=" << s << ", maxlen=" << len;

    int result = Real_recv(s, buf, len, flags);

    std::ostringstream ret;
    ret << result << " bytes";
    if (result > 0 && result <= 256 && buf) {
        ret << " Data=[";
        for (int i = 0; i < min(result, 32); i++)
            ret << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)buf[i] << " ";
        if (result > 32) ret << "...";
        ret << "]";
    }

    LOG_API_CALL("ws2_32.dll", "recv", params.str(), ret.str(), ApiCategory::NETWORK_COMMUNICATION);
    return result;
}

HINTERNET WINAPI Hook_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) {
    std::ostringstream params;
    params << "Agent=" << FmtStrW(pszAgentW) << ", AccessType=" << dwAccessType;

    HINTERNET result = Real_WinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);

    LOG_API_CALL("winhttp.dll", "WinHttpOpen", params.str(), FmtHandle(result), ApiCategory::NETWORK_COMMUNICATION);
    return result;
}

HINTERNET WINAPI Hook_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
    std::ostringstream params;
    params << "hSession=" << FmtHandle(hSession) << ", Server=" << FmtStrW(pswzServerName) << ", Port=" << nServerPort;

    HINTERNET result = Real_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);

    LOG_API_CALL("winhttp.dll", "WinHttpConnect", params.str(), FmtHandle(result), ApiCategory::NETWORK_COMMUNICATION);
    return result;
}

HRESULT WINAPI Hook_URLDownloadToFileW(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB) {
    std::ostringstream params;
    params << "URL=" << FmtStrW(szURL) << ", File=" << FmtStrW(szFileName);

    HRESULT result = Real_URLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);

    std::ostringstream ret;
    ret << "0x" << std::hex << result;

    LOG_API_CALL("urlmon.dll", "URLDownloadToFileW", params.str(), ret.str(), ApiCategory::NETWORK_COMMUNICATION);
    return result;
}

void InstallNetworkHooks() {
    HOOK_API_WS2_32("socket", Hook_socket, Real_socket);
    HOOK_API_WS2_32("connect", Hook_connect, Real_connect);
    HOOK_API_WS2_32("bind", Hook_bind, Real_bind);
    HOOK_API_WS2_32("listen", Hook_listen, Real_listen);
    HOOK_API_WS2_32("accept", Hook_accept, Real_accept);
    HOOK_API_WS2_32("send", Hook_send, Real_send);
    HOOK_API_WS2_32("recv", Hook_recv, Real_recv);
    HOOK_API_WS2_32("WSAStartup", Hook_WSAStartup, Real_WSAStartup);
    HOOK_API_WS2_32("WSACleanup", Hook_WSACleanup, Real_WSACleanup);
    HOOK_API_WS2_32("closesocket", Hook_closesocket, Real_closesocket);

    HOOK_API_WINHTTP("WinHttpOpen", Hook_WinHttpOpen, Real_WinHttpOpen);
    HOOK_API_WINHTTP("WinHttpConnect", Hook_WinHttpConnect, Real_WinHttpConnect);
    HOOK_API_WINHTTP("WinHttpOpenRequest", Hook_WinHttpOpenRequest, Real_WinHttpOpenRequest);
    HOOK_API_WINHTTP("WinHttpSendRequest", Hook_WinHttpSendRequest, Real_WinHttpSendRequest);
    HOOK_API_WINHTTP("WinHttpReceiveResponse", Hook_WinHttpReceiveResponse, Real_WinHttpReceiveResponse);
    HOOK_API_WINHTTP("WinHttpReadData", Hook_WinHttpReadData, Real_WinHttpReadData);
    HOOK_API_WINHTTP("WinHttpCloseHandle", Hook_WinHttpCloseHandle, Real_WinHttpCloseHandle);

    HOOK_API_WININET("InternetOpenA", Hook_InternetOpenA, Real_InternetOpenA);
    HOOK_API_WININET("InternetConnectA", Hook_InternetConnectA, Real_InternetConnectA);
    HOOK_API_WININET("InternetCloseHandle", Hook_InternetCloseHandle, Real_InternetCloseHandle);

    HOOK_API_FULL("urlmon.dll", "URLDownloadToFileW", Hook_URLDownloadToFileW, Real_URLDownloadToFileW);
}