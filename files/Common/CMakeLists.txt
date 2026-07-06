add_library(Common STATIC
        ApiDatabase.cpp
        Config.cpp
)

target_include_directories(Common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(Common PUBLIC ${MINHOOK_LIB_NAME})