# PCAP数据包回放工具

一个可以捕获、存储和回放PCAP文件中网络流量的工具。

## 功能特性
- 服务端组件用于接收和存储PCAP数据
- 客户端组件用于回放捕获的数据包
- 支持多并发连接
- 线程安全的数据包处理

## 构建说明

```bash
mkdir build && cd build
cmake ..
make
```

## 使用方法

### 服务端
```bash
./build/pcap_server [端口号]
```

### 客户端
```bash
./build/pcap_client [服务器IP] [服务器端口] [pcap文件]
```

## 系统要求
- CMake 3.10+
- 支持C++17的编译器
- libpcap开发库

## 许可证
MIT

---

# PCAP Replay Software (English)

A network packet replay tool that can capture, store and replay network traffic from PCAP files.

## Features
- Server component for receiving and storing PCAP data
- Client component for replaying captured packets
- Support for multiple concurrent connections
- Thread-safe packet handling

## Build Instructions

```bash
mkdir build && cd build
cmake ..
make
```

## Usage

### Server
```bash
./build/pcap_server [port]
```

### Client
```bash
./build/pcap_client [server_ip] [server_port] [pcap_file]
```

## Requirements
- CMake 3.10+
- C++17 compatible compiler
- libpcap development libraries

## License
MIT
