cmake_minimum_required(VERSION 3.10)
project(process-hallowing-poc C CXX)

include(${CMAKE_SOURCE_DIR}/cmake/common.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/windows_manifest.cmake)

add_executable(${PROJECT_NAME} 
    src/main.cpp
)

add_subdirectory(libs/phnt)

target_link_libraries(${PROJECT_NAME} PRIVATE phnt::phnt)
target_sources(${PROJECT_NAME} PRIVATE app.rc)
enable_optional_manifest(${PROJECT_NAME})
