#include <iostream>
#include <cstdio>
#include <vector>
#include <string>

typedef struct Packet_ {
    int frame_number;
    std::string time;
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    std::string info;
} Packet;

void parseLine(std::string line, Packet& packet) {
    std::vector<std::string> fields;
    size_t start = 0;
    size_t end;

    if (line.back() == '\n')
        line.pop_back();

    /* split the origin data */
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start));

    if (fields.size() >= 6) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.src_ip = fields[2];
        packet.dst_ip = fields[3];
        packet.protocol = fields[4];
        packet.info = fields[5];
    }
    else {
        std::cerr << "Error: Not enough fields in line." << std::endl;
    }

    return;
}

int main()
{
    const char* read_pcap_cmd = "tshark \
            -r E:/Proj/nb_easy_tshark/pcap/capture.pcap \
            -T fields -e frame.number   \
            -e frame.time               \
            -e ip.src                   \
            -e ip.dst                   \
            -e _ws.col.Protocol         \
            -e _ws.col.Info";
    FILE* pipe = _popen(read_pcap_cmd, "r");
    if (!pipe) {
        std::cerr << "Fail to read pcap by tshark!" << std::endl;
        return 1;
    }

    char buffer[4096];
    std::vector<Packet> vec_packets;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        parseLine(buffer, packet);
        vec_packets.push_back(packet);
    }
    _pclose(pipe);

    for (const auto& pkt : vec_packets) {
        printf("frame_id: %d, time: %s, src ip: %s, dst ip: %s, protocol: %s, info: %s\n",
            pkt.frame_number,       \
            pkt.time.c_str(),       \
            pkt.src_ip.c_str(),     \
            pkt.dst_ip.c_str(),     \
            pkt.protocol.c_str(),   \
            pkt.info.c_str());
    }

    return 0;
}

