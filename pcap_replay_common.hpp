#ifndef PCAP_REPLAY_COMMON_HPP
#define PCAP_REPLAY_COMMON_HPP

#include <vector>
#include <cstdint>

// 定义服务器端口
constexpr uint16_t SERVER_PORT = 8888;

// 状态枚举
enum class ReplayState {
    IDLE,           // 空闲状态
    SENDING,        // 发送中
    SEND_COMPLETED, // 发送完成
    RECEIVING       // 接收中
};

// 数据包结构
struct Packet {
    std::vector<uint8_t> data;
    uint64_t timestamp; // 时间戳，单位为微秒
    bool is_outgoing;   // 标记是发送还是接收
};

#endif // PCAP_REPLAY_COMMON_HPP    