# Specify the minimum version of CMake
cmake_minimum_required(VERSION 3.16)

# Project name and version
project(BobaSshServer VERSION 1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add the executable for your program
add_executable(BobaSshServer BobaSshServer.cpp)

# Link the pthread library
target_link_libraries(BobaSshServer pthread)

# Optional: Set include directories if you have headers
# target_include_directories(BobaSshServer PRIVATE include/)

# Optional: Compiler flags for optimization/debugging
if(CMAKE_BUILD_TYPE MATCHES Debug)
    message("Compiling in Debug mode")
    set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -pedantic")
else()
    message("Compiling in Release mode")
    set(CMAKE_CXX_FLAGS "-O2")
endif()

# Optional: Output directories for compiled binary
set_target_properties(BobaSshServer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
