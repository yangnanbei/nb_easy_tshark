#pragma once

typedef struct Packet_ {
    int frame_number;
    std::string time;
    std::string src_ip;
    std::string dst_ip;
    int src_port;
    int dst_port;
    std::string protocol;
    std::string info;
} Packet;

bool parseLine(std::string line, Packet& packet);
