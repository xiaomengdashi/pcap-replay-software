#include "pcap_client.hpp"
#include <iostream>
#include <chrono>
#include <thread>

PcapClient::PcapClient(const std::string& server_ip, uint16_t server_port)
    : socket_(io_context_, boost::asio::ip::udp::v4()),
      server_endpoint_(boost::asio::ip::make_address(server_ip), server_port),
      receive_buffer_(65536),
      next_packet_index_(0),
      running_(false),
      current_state_(ReplayState::IDLE) {
}

PcapClient::~PcapClient() {
    stop();
}

bool PcapClient::startReplay(const std::vector<Packet>& packets, 
                            const std::string& client_ip,
                            const std::string& server_ip_pcap) {
    if (running_) {
        std::cerr << "Client is already running" << std::endl;
        return false;
    }

    packets_ = packets;
    client_ip_ = client_ip;
    server_ip_pcap_ = server_ip_pcap;
    next_packet_index_ = 0;
    running_ = true;
    transitionState(ReplayState::IDLE);

    // 启动接收线程
    startReceive();
    
    // 启动回放线程
    replay_thread_ = std::thread([this]() {
        try {
            processPackets();
        } catch (const std::exception& e) {
            std::cerr << "Error in replay thread: " << e.what() << std::endl;
        }
    });

    return true;
}

void PcapClient::stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    
    try {
        if (socket_.is_open()) {
            socket_.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to close socket: " << e.what() << std::endl;
    }

    if (replay_thread_.joinable()) {
        cv_.notify_one();
        replay_thread_.join();
    }
    
    transitionState(ReplayState::IDLE);
}

ReplayState PcapClient::getState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_state_;
}

std::string PcapClient::getStateString() const {
    ReplayState state = getState();
    switch (state) {
        case ReplayState::IDLE: return "IDLE";
        case ReplayState::SENDING: return "SENDING";
        case ReplayState::SEND_COMPLETED: return "SEND_COMPLETED";
        case ReplayState::RECEIVING: return "RECEIVING";
        default: return "UNKNOWN";
    }
}

void PcapClient::startReceive() {
    socket_.async_receive_from(
        boost::asio::buffer(receive_buffer_), server_endpoint_,
        [this](const boost::system::error_code& error, std::size_t bytes_transferred) {
            handleReceive(error, bytes_transferred);
        });
}

void PcapClient::handleReceive(const boost::system::error_code& error, 
                              std::size_t bytes_transferred) {
    if (!error && running_) {
        // 复制接收到的数据
        Packet received;
        received.data.resize(bytes_transferred);
        std::copy_n(receive_buffer_.data(), bytes_transferred, received.data.begin());
        received.timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        received.is_outgoing = false; // 接收到的包标记为非外发
        
        // 将接收到的数据包放入队列
        {
            std::lock_guard<std::mutex> lock(mutex_);
            received_packets_.push(std::move(received));
        }
        
        // 通知回放线程
        cv_.notify_one();
        
        // 继续接收
        if (running_) {
            startReceive();
        }
    }
}

void PcapClient::sendPacket(const Packet& packet) {
    try {
        // 发送数据包
        size_t bytes_sent = socket_.send_to(
            boost::asio::buffer(packet.data), server_endpoint_);
        
        if (bytes_sent != packet.data.size()) {
            std::cerr << "Failed to send entire packet" << std::endl;
        } else {
            std::cout << "Client sent packet of size: " << packet.data.size() 
                      << " (state: " << getStateString() << ")" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error sending packet: " << e.what() << std::endl;
    }
}

void PcapClient::transitionState(ReplayState newState) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (current_state_ != newState) {
        std::cout << "Client state transition: " 
                  << getStateString() << " -> ";
        current_state_ = newState;
        std::cout << getStateString() << std::endl;
    }
}

void PcapClient::processPackets() {
    if (packets_.empty()) {
        std::cerr << "No packets to process" << std::endl;
        transitionState(ReplayState::IDLE);
        return;
    }

    // 记录开始时间
    auto start_time = std::chrono::high_resolution_clock::now();
    uint64_t first_timestamp = packets_[0].timestamp;

    // 发送第一条数据
    if (next_packet_index_ < packets_.size()) {
        const Packet& first_packet = packets_[next_packet_index_];
        if (first_packet.is_outgoing) {
            transitionState(ReplayState::SENDING);
            
            // 计算应该发送的时间点
            uint64_t time_offset = first_packet.timestamp - first_timestamp;
            auto target_time = start_time + std::chrono::microseconds(time_offset);
            
            // 等待到正确的时间发送
            auto now = std::chrono::high_resolution_clock::now();
            if (target_time > now) {
                std::this_thread::sleep_for(target_time - now);
            }
            
            // 发送第一个包
            sendPacket(first_packet);
            ++next_packet_index_;
            
            transitionState(ReplayState::SEND_COMPLETED);
        } else {
            std::cerr << "First packet is not outgoing" << std::endl;
            transitionState(ReplayState::IDLE);
            return;
        }
    }

    // 处理剩余的数据包
    while (running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        // 如果下一个包是发送，直接发送
        if (next_packet_index_ < packets_.size() && 
            packets_[next_packet_index_].is_outgoing) {
            transitionState(ReplayState::SENDING);
            
            const Packet& packet = packets_[next_packet_index_];
            
            // 计算应该发送的时间点
            uint64_t time_offset = packet.timestamp - first_timestamp;
            auto target_time = start_time + std::chrono::microseconds(time_offset);
            
            // 等待到正确的时间发送
            auto now = std::chrono::high_resolution_clock::now();
            if (target_time > now) {
                lock.unlock();
                std::this_thread::sleep_for(target_time - now);
                lock.lock();
            }
            
            // 发送数据包
            sendPacket(packet);
            ++next_packet_index_;
            
            transitionState(ReplayState::SEND_COMPLETED);
        } 
        // 否则等待接收数据
        else if (next_packet_index_ < packets_.size()) {
            transitionState(ReplayState::RECEIVING);
            
            // 等待有新的数据包到达
            cv_.wait(lock, [this]() {
                return !received_packets_.empty() || !running_;
            });
            
            if (!running_) {
                break;
            }
            
            // 处理接收到的数据包
            bool packet_matched = false;
            while (!received_packets_.empty() && 
                   next_packet_index_ < packets_.size() &&
                   !packets_[next_packet_index_].is_outgoing) {
                Packet received = std::move(received_packets_.front());
                received_packets_.pop();
                
                // 在这里可以根据接收到的数据包内容决定下一步操作
                std::cout << "Client received packet of size: " << received.data.size() 
                          << " (state: " << getStateString() << ")" << std::endl;
                
                // 匹配预期接收包
                ++next_packet_index_;
                packet_matched = true;
            }
            
            if (packet_matched) {
                transitionState(ReplayState::SEND_COMPLETED);
            }
        }
        
        // 检查是否所有包都已处理
        if (next_packet_index_ >= packets_.size()) {
            std::cout << "Client packet replay completed" << std::endl;
            transitionState(ReplayState::IDLE);
            break;
        }
    }
}
