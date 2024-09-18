cmake_minimum_required(VERSION 3.16)
project(MemoryScanner)

set(CMAKE_CXX_STANDARD 17)

# Specify the path to the Qt installation
set(CMAKE_PREFIX_PATH "C:\\Qt\\6.7.2\\msvc2019_64")

# Locate Qt 6
find_package(Qt6 REQUIRED COMPONENTS Widgets)

# Include MOC and UIC directories
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Add executable
add_executable(MemoryScanner
    MemoryScanner.cpp
    MemoryScanner.h
)

# Link Qt libraries
target_link_libraries(MemoryScanner Qt6::Widgets)

# Set include directories
target_include_directories(MemoryScanner PRIVATE ${Qt6_INCLUDE_DIRS})
