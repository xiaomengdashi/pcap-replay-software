#ifndef PCAP_READER_HPP
#define PCAP_READER_HPP

#include <string>
#include <vector>
#include "pcap_replay_common.hpp"

class PcapReader {
public:
    PcapReader(const std::string& filename);
    ~PcapReader();

    bool open();
    void close();
    bool isOpen() const;

    bool readPackets(std::vector<Packet>& packets, 
                     std::string& client_ip, 
                     std::string& server_ip,
                     bool replace_ips = false,
                     const std::string& new_client_ip = "",
                     const std::string& new_server_ip = "");

private:
    std::string filename_;
    FILE* file_ = nullptr;
};

#endif // PCAP_READER_HPP    