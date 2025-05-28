#ifndef PCAP_SERVER_HPP
#define PCAP_SERVER_HPP

#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <boost/asio.hpp>
#include "pcap_replay_common.hpp"

struct ReplayStatistics {
    uint64_t total_packets_sent;
    uint64_t total_packets_received;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    uint64_t matched_packets;
    uint64_t mismatched_packets;
};

class PcapServer {
public:
    PcapServer(uint16_t port);
    ~PcapServer();

    bool startReplay(const std::vector<Packet>& packets, 
                    const std::string& client_ip,
                    const std::string& server_ip_pcap);
    void stop();
    ReplayState getState() const;
    std::string getStateString() const;
    ReplayStatistics getStatistics() const;

private:
    void startReceive();
    void handleReceive(const boost::system::error_code& error, 
                      std::size_t bytes_transferred);
    void sendPacket(const Packet& packet);
    void processPackets();
    void transitionState(ReplayState newState);

    boost::asio::io_context io_context_;
    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint client_endpoint_;
    std::vector<uint8_t> receive_buffer_;
    
    std::vector<Packet> packets_;
    std::string client_ip_;
    std::string server_ip_pcap_;
    size_t next_packet_index_;
    bool running_;
    std::thread replay_thread_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<Packet> received_packets_;
    ReplayState current_state_;

    // Statistics
    uint64_t total_packets_sent_ = 0;
    uint64_t total_packets_received_ = 0;
    uint64_t total_bytes_sent_ = 0;
    uint64_t total_bytes_received_ = 0;
    uint64_t matched_packets_ = 0;
    uint64_t mismatched_packets_ = 0;
};

#endif // PCAP_SERVER_HPP
