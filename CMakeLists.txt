cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(sigmaker)

set(CMAKE_CXX_STANDARD 23)

include($ENV{IDASDK}/ida-cmake/idasdk.cmake)

set(PLUGIN_NAME sigmaker)
set(PLUGIN_SOURCES
    "src/Main.cpp"
    "src/Plugin.cpp"
    "src/SignatureUtils.cpp"
    "src/Utils.cpp"
)

generate()
