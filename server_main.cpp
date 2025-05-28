#include <iostream>
#include <thread>
#include <chrono>
#include "pcap_reader.hpp"
#include "pcap_server.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    std::string pcap_file = argv[1];

    // 读取PCAP文件
    PcapReader reader(pcap_file);
    std::vector<Packet> packets;
    std::string client_ip, server_ip_pcap;
    
    if (!reader.readPackets(packets, client_ip, server_ip_pcap)) {
        std::cerr << "Failed to read PCAP file" << std::endl;
        return 1;
    }

    std::cout << "Client IP: " << client_ip << std::endl;
    std::cout << "Server IP (from PCAP): " << server_ip_pcap << std::endl;
    std::cout << "Number of packets read: " << packets.size() << std::endl;

    // 创建并运行服务器
    PcapServer server(SERVER_PORT);
    std::cout << "Starting server on port " << SERVER_PORT << std::endl;
    
    if (!server.startReplay(packets, client_ip, server_ip_pcap)) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    // 定期显示状态
    std::thread status_thread([&server]() {
        while (server.getState() != ReplayState::IDLE) {
            std::cout << "Current server state: " << server.getStateString() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    std::cout << "Server running. Press Enter to stop..." << std::endl;
    std::cin.get();

    server.stop();
    if (status_thread.joinable()) {
        status_thread.join();
    }
    std::cout << "Server stopped" << std::endl;
    return 0;
}    