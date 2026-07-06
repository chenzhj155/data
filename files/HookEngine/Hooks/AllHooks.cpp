#include "AllHooks.h"
#include "../HookEngine.h"
#include <map>
#include <functional>

// ============================================
// 安装函数声明
// ============================================
void InstallFileHooks();
void InstallRegistryHooks();
void InstallMemoryHooks();
void InstallProcessHooks();
void InstallThreadHooks();
void InstallNetworkHooks();
void InstallSyncHooks();
void InstallCryptoHooks();
void InstallInjectionHooks();
void InstallAntiDebugHooks();
void InstallSystemInfoHooks();

void InstallAllApiHooks() {
    OutputDebugStringA("[ApiMonitor] Installing File hooks...\n");
    InstallFileHooks();

    OutputDebugStringA("[ApiMonitor] Installing Registry hooks...\n");
    InstallRegistryHooks();

    OutputDebugStringA("[ApiMonitor] Installing Memory hooks...\n");
    InstallMemoryHooks();

    OutputDebugStringA("[ApiMonitor] Installing Process hooks...\n");
    InstallProcessHooks();

    OutputDebugStringA("[ApiMonitor] Installing Thread hooks...\n");
    InstallThreadHooks();

    OutputDebugStringA("[ApiMonitor] Installing Network hooks...\n");
    InstallNetworkHooks();

    OutputDebugStringA("[ApiMonitor] Installing Sync hooks...\n");
    InstallSyncHooks();

    OutputDebugStringA("[ApiMonitor] Installing Crypto hooks...\n");
    InstallCryptoHooks();

    OutputDebugStringA("[ApiMonitor] Installing Injection hooks...\n");
    InstallInjectionHooks();

    OutputDebugStringA("[ApiMonitor] Installing AntiDebug hooks...\n");
    InstallAntiDebugHooks();

    OutputDebugStringA("[ApiMonitor] Installing SystemInfo hooks...\n");
    InstallSystemInfoHooks();

    OutputDebugStringA("[ApiMonitor] All hooks installed successfully!\n");
}