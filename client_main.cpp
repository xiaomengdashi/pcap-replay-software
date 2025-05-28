#include <iostream>
#include <thread>
#include <chrono>
#include "pcap_reader.hpp"
#include "pcap_client.hpp"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> <server_ip>" << std::endl;
        return 1;
    }

    std::string pcap_file = argv[1];
    std::string server_ip = argv[2];

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

    // 创建并运行客户端
    PcapClient client(server_ip, SERVER_PORT);
    std::cout << "Starting client replay..." << std::endl;
    
    if (!client.startReplay(packets, client_ip, server_ip_pcap)) {
        std::cerr << "Failed to start client" << std::endl;
        return 1;
    }

    // 定期显示状态
    std::thread status_thread([&client]() {
        while (client.getState() != ReplayState::IDLE) {
            std::cout << "Current client state: " << client.getStateString() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    std::cout << "Client running. Press Enter to stop..." << std::endl;
    std::cin.get();

    client.stop();
    if (status_thread.joinable()) {
        status_thread.join();
    }
    std::cout << "Client stopped" << std::endl;
    return 0;
}    