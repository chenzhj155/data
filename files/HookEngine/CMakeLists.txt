add_library(HookEngine SHARED
        dllmain.cpp
        HookEngine.cpp
        Filter/CallFilter.cpp
        IPC/PipeServer.cpp
        Hooks/AllHooks.cpp
)

target_include_directories(HookEngine PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/Common
)

target_link_libraries(HookEngine PRIVATE
        Common
        ${MINHOOK_LIB_NAME}
        ws2_32
        winhttp
        wininet
        urlmon
        dnsapi
        mpr
        netapi32
        wtsapi32
        psapi
)

set_target_properties(HookEngine PROPERTIES
        PREFIX ""
        OUTPUT_NAME "HookEngine"
)