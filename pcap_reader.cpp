#include "pcap_reader.hpp"
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct PcapFileHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct TcpHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
};
#pragma pack(pop)

// 计算校验和的辅助函数
uint16_t calculateChecksum(const uint16_t* data, size_t length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length) {
        sum += *(uint8_t*)data;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// 重新计算TCP校验和
void recalculateTcpChecksum(std::vector<uint8_t>& packet_data, size_t ip_header_length) {
    EthernetHeader* eth_header = reinterpret_cast<EthernetHeader*>(packet_data.data());
    IPv4Header* ip_header = reinterpret_cast<IPv4Header*>(packet_data.data() + sizeof(EthernetHeader));
    TcpHeader* tcp_header = reinterpret_cast<TcpHeader*>(packet_data.data() + sizeof(EthernetHeader) + ip_header_length);
    
    // 保存原始校验和
    uint16_t original_checksum = tcp_header->checksum;
    tcp_header->checksum = 0;
    
    // 计算TCP伪首部和数据的校验和
    uint32_t tcp_length = ntohs(ip_header->total_length) - ip_header_length;
    uint32_t sum = 0;
    
    // 伪首部
    sum += (ip_header->src_ip >> 16) & 0xFFFF;
    sum += ip_header->src_ip & 0xFFFF;
    sum += (ip_header->dest_ip >> 16) & 0xFFFF;
    sum += ip_header->dest_ip & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcp_length);
    
    // TCP头部和数据
    const uint16_t* tcp_data = reinterpret_cast<const uint16_t*>(tcp_header);
    size_t tcp_data_length = tcp_length;
    
    while (tcp_data_length > 1) {
        sum += *tcp_data++;
        tcp_data_length -= 2;
    }
    
    if (tcp_data_length) {
        sum += *reinterpret_cast<const uint8_t*>(tcp_data) << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    tcp_header->checksum = static_cast<uint16_t>(~sum);
}

PcapReader::PcapReader(const std::string& filename) : filename_(filename) {}

PcapReader::~PcapReader() {
    close();
}

bool PcapReader::open() {
    file_ = fopen(filename_.c_str(), "rb");
    return file_ != nullptr;
}

void PcapReader::close() {
    if (file_) {
        fclose(file_);
        file_ = nullptr;
    }
}

bool PcapReader::isOpen() const {
    return file_ != nullptr;
}

bool PcapReader::readPackets(std::vector<Packet>& packets, 
                             std::string& client_ip, 
                             std::string& server_ip,
                             bool replace_ips,
                             const std::string& new_client_ip,
                             const std::string& new_server_ip) {
    if (!isOpen() && !open()) {
        std::cerr << "Failed to open PCAP file: " << filename_ << std::endl;
        return false;
    }

    // 读取文件头
    PcapFileHeader file_header;
    if (fread(&file_header, sizeof(file_header), 1, file_) != 1) {
        std::cerr << "Failed to read PCAP file header" << std::endl;
        return false;
    }

    // 检查文件格式
    if (file_header.magic_number != 0xa1b2c3d4 && 
        file_header.magic_number != 0xd4c3b2a1) {
        std::cerr << "Not a valid PCAP file" << std::endl;
        return false;
    }

    // 处理字节序
    bool need_swap = (file_header.magic_number == 0xd4c3b2a1);
    auto swap_if_needed = [need_swap](uint32_t value) {
        return need_swap ? ntohl(value) : value;
    };

    // 转换用户提供的IP地址
    in_addr new_client_ip_bin, new_server_ip_bin;
    if (replace_ips) {
        if (inet_pton(AF_INET, new_client_ip.c_str(), &new_client_ip_bin) != 1 ||
            inet_pton(AF_INET, new_server_ip.c_str(), &new_server_ip_bin) != 1) {
            std::cerr << "Invalid IP address format" << std::endl;
            return false;
        }
    }

    // 查找两个IP地址
    bool found_ip1 = false, found_ip2 = false;
    in_addr ip1, ip2;

    // 读取所有数据包
    PcapPacketHeader packet_header;
    while (fread(&packet_header, sizeof(packet_header), 1, file_) == 1) {
        uint32_t incl_len = swap_if_needed(packet_header.incl_len);
        uint32_t orig_len = swap_if_needed(packet_header.orig_len);
        uint32_t ts_sec = swap_if_needed(packet_header.ts_sec);
        uint32_t ts_usec = swap_if_needed(packet_header.ts_usec);

        // 分配内存并读取数据包内容
        std::vector<uint8_t> packet_data(incl_len);
        if (fread(packet_data.data(), incl_len, 1, file_) != 1) {
            std::cerr << "Failed to read packet data" << std::endl;
            return false;
        }

        // 初始化方向标志
        bool is_outgoing = false;
        
        // 提取IP地址（如果是IPv4包）
        if (incl_len >= sizeof(EthernetHeader) + sizeof(IPv4Header)) {
            EthernetHeader* eth_header = reinterpret_cast<EthernetHeader*>(packet_data.data());
            uint16_t eth_type = ntohs(eth_header->eth_type);
            
            if (eth_type == 0x0800) { // IPv4
                IPv4Header* ip_header = reinterpret_cast<IPv4Header*>(packet_data.data() + sizeof(EthernetHeader));
                uint8_t ihl = ip_header->version_ihl & 0x0F;
                size_t ip_header_length = ihl * 4;
                
                if (ihl >= 5 && ip_header_length <= incl_len - sizeof(EthernetHeader)) {
                    in_addr src_ip, dest_ip;
                    src_ip.s_addr = ip_header->src_ip;
                    dest_ip.s_addr = ip_header->dest_ip;

                    // 查找两个IP地址
                    if (!found_ip1) {
                        ip1 = src_ip;
                        found_ip1 = true;
                    } else if (!found_ip2 && 
                              (src_ip.s_addr != ip1.s_addr)) {
                        ip2 = src_ip;
                        found_ip2 = true;
                    }
                    
                    if (!found_ip2 && 
                        (dest_ip.s_addr != ip1.s_addr)) {
                        ip2 = dest_ip;
                        found_ip2 = true;
                    }

                    // 确定数据包方向
                    if (found_ip1 && found_ip2) {
                        // 假设ip1是客户端，ip2是服务器
                        is_outgoing = (src_ip.s_addr == ip1.s_addr);
                    }

                    // 如果启用了IP替换
                    if (replace_ips) {
                        // 保存原始IP
                        in_addr original_src = src_ip;
                        in_addr original_dest = dest_ip;
                        
                        // 替换源IP和目标IP
                        if (is_outgoing) {
                            ip_header->src_ip = new_client_ip_bin.s_addr;
                            ip_header->dest_ip = new_server_ip_bin.s_addr;
                        } else {
                            ip_header->src_ip = new_server_ip_bin.s_addr;
                            ip_header->dest_ip = new_client_ip_bin.s_addr;
                        }
                        
                        // 重新计算IP校验和
                        ip_header->checksum = 0;
                        ip_header->checksum = calculateChecksum(
                            reinterpret_cast<const uint16_t*>(ip_header), 
                            ip_header_length);
                        
                        // 如果是TCP包，重新计算TCP校验和
                        if (ip_header->protocol == IPPROTO_TCP &&
                            incl_len >= sizeof(EthernetHeader) + ip_header_length + sizeof(TcpHeader)) {
                            recalculateTcpChecksum(packet_data, ip_header_length);
                        }
                        
                        std::cout << "Replaced IP: " 
                                  << inet_ntoa(original_src) << " -> " << inet_ntoa(*(in_addr*)&ip_header->src_ip) 
                                  << " | " 
                                  << inet_ntoa(original_dest) << " -> " << inet_ntoa(*(in_addr*)&ip_header->dest_ip) 
                                  << std::endl;
                    }
                }
            }
        }

        // 保存数据包
        Packet packet;
        packet.data = std::move(packet_data);
        packet.timestamp = static_cast<uint64_t>(ts_sec) * 1000000 + ts_usec;
        packet.is_outgoing = is_outgoing;
        packets.push_back(std::move(packet));
    }

    // 确定客户端和服务器IP
    if (!found_ip1 || !found_ip2) {
        std::cerr << "Could not find two distinct IP addresses in PCAP file" << std::endl;
        return false;
    }

    // 简单地将第一个IP设为客户端，第二个设为服务器
    client_ip = inet_ntoa(ip1);
    server_ip = inet_ntoa(ip2);

    return true;
}    