cmake_minimum_required(VERSION 3.10)
project(PcapReplay)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找Boost库
find_package(Boost REQUIRED COMPONENTS system thread)
include_directories(${Boost_INCLUDE_DIRS})

# 添加可执行文件
add_executable(pcap_client 
    pcap_replay_common.hpp
    pcap_reader.hpp pcap_reader.cpp
    pcap_client.hpp pcap_client.cpp
    client_main.cpp
)

add_executable(pcap_server 
    pcap_replay_common.hpp
    pcap_reader.hpp pcap_reader.cpp
    pcap_server.hpp pcap_server.cpp
    server_main.cpp
)

# 链接Boost库
target_link_libraries(pcap_client ${Boost_LIBRARIES} pthread)
target_link_libraries(pcap_server ${Boost_LIBRARIES} pthread)    