#include "PipeServer.h"

PipeServer::PipeServer(const std::string& name)
    : m_pipeName("\\\\.\\pipe\\" + name) {
}

PipeServer::~PipeServer() {
    Stop();
}

bool PipeServer::Start() {
    if (m_running) return true;
    m_running = true;

    m_acceptThread = std::thread(&PipeServer::AcceptLoop, this);
    return true;
}

void PipeServer::Stop() {
    m_running = false;

    // 关闭管道以唤醒等待的线程
    if (m_pipe != INVALID_HANDLE_VALUE) {
        if (m_connected) {
            DisconnectNamedPipe(m_pipe);
        }
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
    m_connected = false;

    if (m_acceptThread.joinable()) {
        m_acceptThread.join();
    }
}

void PipeServer::AcceptLoop() {
    while (m_running) {
        m_pipe = CreateNamedPipeA(
            m_pipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,              // 最多1个实例
            65536,          // 输出缓冲区
            65536,          // 输入缓冲区
            0,              // 默认超时
            NULL            // 默认安全属性
        );

        if (m_pipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        // 等待客户端连接
        BOOL connected = ConnectNamedPipe(m_pipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(m_pipe);
            m_pipe = INVALID_HANDLE_VALUE;
            Sleep(1000);
            continue;
        }

        m_connected = true;
        OutputDebugStringA("[ApiMonitor] IPC client connected\n");

        // 处理消息循环
        char buffer[65536];
        DWORD bytesRead;

        while (m_running && m_connected) {
            BOOL success = ReadFile(m_pipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
            if (!success || bytesRead == 0) {
                break;
            }

            buffer[bytesRead] = '\0';
            std::string msg(buffer);

            // 处理命令
            if (msg == "SHUTDOWN") {
                OutputDebugStringA("[ApiMonitor] Received shutdown command\n");
                break;
            } else if (msg == "STATUS") {
                // 发送状态信息
                char status[512];
                sprintf_s(status, "Total API calls: %zu\n",
                         ApiDatabase::GetInstance().GetTotalCalls());
                DWORD written;
                WriteFile(m_pipe, status, (DWORD)strlen(status) + 1, &written, NULL);
            }
        }

        // 客户端断开连接
        DisconnectNamedPipe(m_pipe);
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
        m_connected = false;
    }
}

bool PipeServer::SendMessage(const std::string& msg) {
    if (!m_connected || m_pipe == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten;
    BOOL success = WriteFile(m_pipe, msg.c_str(), (DWORD)msg.length() + 1, &bytesWritten, NULL);
    return success && bytesWritten > 0;
}

std::string PipeServer::ReceiveMessage() {
    if (!m_connected || m_pipe == INVALID_HANDLE_VALUE) return "";

    char buffer[65536];
    DWORD bytesRead;

    BOOL success = ReadFile(m_pipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    if (!success || bytesRead == 0) {
        return "";
    }

    buffer[bytesRead] = '\0';
    return std::string(buffer);
}