#include <windows.h>
#include "HookEngine.h"
#include "ApiDatabase.h"
#include "Config.h"
#include "IPC/PipeServer.h"

PipeServer* g_pipeServer = nullptr;

// 用于 SetWindowsHookEx 注入的导出函数
extern "C" __declspec(dllexport) LRESULT CALLBACK GetMsgProc(int code, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, code, wParam, lParam);
}

// 初始化线程
DWORD WINAPI InitThread(LPVOID param) {
    HMODULE hModule = (HMODULE)param;

    // 等待目标进程完全初始化
    Sleep(100);

    // 获取目标进程名
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeName = GetFileNameFromPath(std::string(exePath));

    // 生成日志文件名
    std::string logPath = exeName + "_api_monitor.log";

    // 如果指定了输出目录
    char* envLogDir = getenv("API_MONITOR_LOG_DIR");
    if (envLogDir) {
        logPath = std::string(envLogDir) + "\\" + logPath;
    }

    // 初始化数据库
    auto& db = ApiDatabase::GetInstance();
    db.Initialize(logPath, false);

    // 初始化 Hook 引擎
    auto& engine = HookEngine::GetInstance();
    if (engine.Initialize(hModule)) {
        engine.InstallAllHooks();
    }

    // 启动 IPC 管道服务器
    char pipeName[256];
    sprintf_s(pipeName, "ApiMonitor_%d", GetCurrentProcessId());
    g_pipeServer = new PipeServer(pipeName);
    g_pipeServer->Start();

    // 发送就绪信号
    OutputDebugStringA("[ApiMonitor] HookEngine initialized successfully\n");
    OutputDebugStringA(("[ApiMonitor] Log file: " + logPath).c_str());

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hModule);

            // 在新线程中初始化，避免阻塞 DllMain
            HANDLE hThread = CreateThread(NULL, 0, InitThread, hModule, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            }
            break;
        }

        case DLL_PROCESS_DETACH: {
            // 清理
            if (g_pipeServer) {
                g_pipeServer->Stop();
                delete g_pipeServer;
                g_pipeServer = nullptr;
            }

            HookEngine::GetInstance().Shutdown();
            ApiDatabase::GetInstance().Shutdown();
            break;
        }
    }

    return TRUE;
}