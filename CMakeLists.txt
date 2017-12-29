cmake_minimum_required(VERSION 3.9)

project(Network_Analyzer)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

add_definitions("-Wall -Wextra -lpcap")

file(GLOB_RECURSE source_files src/*)

add_executable(Network_Analyzer ${source_files} src/dns.h)

target_link_libraries(Network_Analyzer pcap)

