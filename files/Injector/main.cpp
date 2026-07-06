#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include "Injector.h"
#include <tlhelp32.h>

void PrintBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════╗
║           Windows API Monitor - DLL Injector             ║
║         基于 MinHook 的完整 API 调用记录系统              ║
╚══════════════════════════════════════════════════════════╝
)" << std::endl;
}

void PrintUsage() {
    std::cout << "Usage:" << std::endl;
    std::cout << "  ApiMonitor.exe --pid <PID> [dll_path]        # 注入到运行中的进程" << std::endl;
    std::cout << "  ApiMonitor.exe --create <exe_path> [dll_path]  # 创建新进程并注入" << std::endl;
    std::cout << "  ApiMonitor.exe --list                          # 列出所有进程" << std::endl;
    std::cout << "  ApiMonitor.exe --find <process_name>           # 查找进程" << std::endl;
    std::cout << "  ApiMonitor.exe --unload <PID> <dll_name>       # 卸载DLL" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  ApiMonitor.exe --pid 1234" << std::endl;
    std::cout << "  ApiMonitor.exe --pid 1234 C:\\path\\to\\HookEngine.dll" << std::endl;
    std::cout << "  ApiMonitor.exe --create C:\\Windows\\notepad.exe" << std::endl;
    std::cout << "  ApiMonitor.exe --find notepad" << std::endl;
    std::cout << "  ApiMonitor.exe --unload 1234 HookEngine.dll" << std::endl;
}

void ListProcesses() {
    auto processes = ProcessInjector::EnumerateProcesses();

    std::cout << "\n" << std::setw(8) << std::left << "PID"
              << std::setw(40) << std::left << "Process Name"
              << std::setw(10) << "Threads" << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    for (const auto& [pid, name] : processes) {
        std::cout << std::setw(8) << std::left << pid
                  << std::setw(40) << std::left << name << std::endl;
    }

    std::cout << "\nTotal: " << processes.size() << " processes" << std::endl;
}

void FindProcess(const std::string& name) {
    DWORD pid = ProcessInjector::FindProcessByName(name);
    if (pid > 0) {
        std::cout << "[+] Found process '" << name << "' with PID " << pid << std::endl;
        std::cout << "    To inject: ApiMonitor.exe --pid " << pid << std::endl;
    } else {
        std::cout << "[-] Process '" << name << "' not found" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintUsage();

        // 交互模式
        std::cout << "\nEnter PID to inject (or 0 to list processes): ";
        DWORD pid;
        std::cin >> pid;

        if (pid == 0) {
            ListProcesses();
            std::cout << "\nEnter PID to inject: ";
            std::cin >> pid;
        }

        if (pid > 0) {
            std::string dllPath = "HookEngine.dll";
            std::cout << "DLL path [HookEngine.dll]: ";
            std::string input;
            std::cin.ignore();
            std::getline(std::cin, input);
            if (!input.empty()) dllPath = input;

            std::cout << "\n[*] Injecting into PID " << pid << "..." << std::endl;

            if (ProcessInjector::InjectDLL(pid, dllPath)) {
                std::cout << "[+] Injection successful!" << std::endl;
                std::cout << "[*] Log file will be created in the target process directory" << std::endl;
                std::cout << "[*] Log format: <process_name>_api_monitor.log" << std::endl;
            } else {
                std::cerr << "[-] Injection failed! Try running as Administrator." << std::endl;
            }
        }

        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 0;
    }

    std::string command = argv[1];
    std::string defaultDllPath = "HookEngine.dll";

    if (command == "--pid" && argc >= 3) {
        DWORD pid = std::stoul(argv[2]);
        std::string dllPath = (argc >= 4) ? argv[3] : defaultDllPath;

        std::cout << "[*] Target PID: " << pid << std::endl;
        std::cout << "[*] DLL: " << dllPath << std::endl;
        std::cout << "[*] Injecting..." << std::endl;

        if (ProcessInjector::InjectDLL(pid, dllPath)) {
            std::cout << "[+] Injection successful!" << std::endl;
            std::cout << "[*] Check <process_name>_api_monitor.log for API call records" << std::endl;
        } else {
            std::cerr << "[-] Injection failed! Try running as Administrator." << std::endl;
            return 1;
        }
    }
    else if (command == "--create" && argc >= 3) {
        std::string exePath = argv[2];
        std::string dllPath = (argc >= 4) ? argv[3] : defaultDllPath;

        std::cout << "[*] Creating process: " << exePath << std::endl;
        std::cout << "[*] DLL: " << dllPath << std::endl;

        DWORD pid = ProcessInjector::CreateAndInject(exePath, dllPath);
        if (pid > 0) {
            std::cout << "[+] Process created with PID " << pid << std::endl;
            std::cout << "[*] Monitoring active. Check <process_name>_api_monitor.log" << std::endl;
        } else {
            std::cerr << "[-] Failed to create process!" << std::endl;
            return 1;
        }
    }
    else if (command == "--list") {
        ListProcesses();
    }
    else if (command == "--find" && argc >= 3) {
        FindProcess(argv[2]);
    }
    else if (command == "--unload" && argc >= 4) {
        DWORD pid = std::stoul(argv[2]);
        std::string dllName = argv[3];

        std::cout << "[*] Unloading " << dllName << " from PID " << pid << "..." << std::endl;
        if (ProcessInjector::UnloadDLL(pid, dllName)) {
            std::cout << "[+] DLL unloaded successfully" << std::endl;
        } else {
            std::cerr << "[-] Failed to unload DLL" << std::endl;
            return 1;
        }
    }
    else {
        PrintUsage();
        return 1;
    }

    return 0;
}