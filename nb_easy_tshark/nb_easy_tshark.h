#pragma once
#include <iostream>
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>

struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

struct Packet {
    int frame_number;
    std::string time;
    uint32_t cap_len;
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    std::string protocol;
    std::string info;
    uint32_t file_offset;
};

bool parseLine(std::string line, Packet& packet);
