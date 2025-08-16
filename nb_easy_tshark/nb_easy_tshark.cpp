#include <iostream>
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "nb_easy_tshark.h"

bool parseLine(std::string line, Packet& packet) {
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;

    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); 

    // fields：
    // 0: frame.number
    // 1: frame.time
    // 2: ip.src
    // 3: ipv6.src
    // 4: ip.dst
    // 5: ipv6.dst
    // 6: tcp.srcport
    // 7: udp.srcport
    // 8: tcp.dstport
    // 9: udp.dstport
    // 10: _ws.col.Protocol
    // 11: _ws.col.Info
    if (fields.size() >= 12) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.src_ip = fields[2].empty() ? fields[3] : fields[2];
        packet.dst_ip = fields[4].empty() ? fields[5] : fields[4];
        if (!fields[6].empty() || !fields[7].empty()) {
            packet.src_port = std::stoi(fields[6].empty() ? fields[7] : fields[6]);
        }

        if (!fields[8].empty() || !fields[9].empty()) {
            packet.dst_port = std::stoi(fields[8].empty() ? fields[9] : fields[8]);
        }
        packet.protocol = fields[10];
        packet.info = fields[11];
    }
    else {
        if (line == "Active code page: 65001") {
            /* Ignore this line, it's my local env setup */
        }
        else {
            std::cerr << "Error: Not enough fields in line." << std::endl;
        }
        return false;
    }

    return true;
}

void printPacket(const Packet& packet) {

    rapidjson::Document pktObj;
    rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();

    pktObj.SetObject();

    pktObj.AddMember("frame_number", packet.frame_number, allocator);
    pktObj.AddMember("timestamp", rapidjson::Value(packet.time.c_str(), allocator), allocator);
    pktObj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("src_port", packet.src_port, allocator);
    pktObj.AddMember("dst_port", packet.dst_port, allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    std::cout << buffer.GetString() << std::endl;
}

int main()
{
    bool ret;
    // if you need to handle Chinese characters in the output, uncomment this line
    // setlocale(LC_ALL, "zh_CN.UTF-8"); 
    std::string packet_file = "E:/Proj/nb_easy_tshark/pcap/10pkts.pcap";

    std::string read_pcap_cmd = "tshark \
            -r " + packet_file + "      \
            -T fields -e frame.number   \
            -e frame.time               \
            -e ip.src                   \
            -e ipv6.src                 \
            -e ip.dst                   \
            -e ipv6.dst                 \
            -e tcp.srcport              \
            -e udp.srcport              \
            -e tcp.dstport              \
            -e udp.dstport              \
            -e _ws.col.Protocol         \
            -e _ws.col.Info";
    FILE* pipe = _popen(read_pcap_cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "Fail to read pcap by tshark!" << std::endl;
        return 1;
    }

    char buffer[4096];
    std::vector<Packet> vec_packets;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        ret = parseLine(buffer, packet);
        if (ret) {
            vec_packets.push_back(packet);
        }
    }
    _pclose(pipe);

    for (const auto& pkt : vec_packets) {
        printPacket(pkt);
    }

    return 0;
}

