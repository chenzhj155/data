#pragma once

#include <windows.h>
#include <string>
#include <atomic>
#include <thread>

class PipeServer {
public:
    PipeServer(const std::string& name);
    ~PipeServer();

    bool Start();
    void Stop();
    bool SendMessage(const std::string& msg);
    std::string ReceiveMessage();
    bool IsConnected() const { return m_connected; }

private:
    void AcceptLoop();

    std::string m_pipeName;
    HANDLE m_pipe = INVALID_HANDLE_VALUE;
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_running{false};
    std::thread m_acceptThread;
};