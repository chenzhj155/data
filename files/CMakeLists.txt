cmake_minimum_required(VERSION 3.20)
project(ApiMonitor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MinHook 路径配置
set(MINHOOK_ROOT "${CMAKE_SOURCE_DIR}/external/minhook" CACHE PATH "MinHook root path")
set(MINHOOK_INCLUDE_DIR "${MINHOOK_ROOT}/include")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MINHOOK_LIB_DIR "${MINHOOK_ROOT}/lib")
    set(MINHOOK_LIB_NAME "libMinHook.x64")
else()
    set(MINHOOK_LIB_DIR "${MINHOOK_ROOT}/lib")
    set(MINHOOK_LIB_NAME "libMinHook.x86")
endif()

# 全局包含目录
include_directories(
        ${CMAKE_SOURCE_DIR}/Common
        ${MINHOOK_INCLUDE_DIR}
)

# 全局库目录
link_directories(${MINHOOK_LIB_DIR})

# 子项目
add_subdirectory(Common)
add_subdirectory(HookEngine)
add_subdirectory(Injector)