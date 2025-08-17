#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "nb_easy_tshark.h"
#include "ip2region_util.h"

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
    // 2: frame.cap_len
    // 3: ip.src
    // 4: ipv6.src
    // 5: ip.dst
    // 6: ipv6.dst
    // 7: tcp.srcport
    // 8: udp.srcport
    // 9: tcp.dstport
    // 10: udp.dstport
    // 11: _ws.col.Protocol
    // 12: _ws.col.Info
    if (fields.size() >= 13) {
        packet.frame_number = std::stoi(fields[0]);
        packet.time = fields[1];
        packet.cap_len = std::stoi(fields[2]);
        packet.src_ip = fields[3].empty() ? fields[4] : fields[3];
        packet.dst_ip = fields[5].empty() ? fields[6] : fields[5];
        if (!fields[7].empty() || !fields[8].empty()) {
            packet.src_port = std::stoi(fields[7].empty() ? fields[8] : fields[7]);
        }

        if (!fields[9].empty() || !fields[10].empty()) {
            packet.dst_port = std::stoi(fields[9].empty() ? fields[10] : fields[9]);
        }
        packet.protocol = fields[11];
        packet.info = fields[12];
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
    pktObj.AddMember("src_location", rapidjson::Value(IP2RegionUtil::getIpLocation(packet.src_ip).c_str(), allocator), allocator);
    pktObj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
    pktObj.AddMember("dst_location", rapidjson::Value(IP2RegionUtil::getIpLocation(packet.dst_ip).c_str(), allocator), allocator);
    pktObj.AddMember("src_port", packet.src_port, allocator);
    pktObj.AddMember("dst_port", packet.dst_port, allocator);
    pktObj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
    pktObj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);
    pktObj.AddMember("file_offset", packet.file_offset, allocator);
    pktObj.AddMember("caplen", packet.cap_len, allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    std::cout << buffer.GetString() << std::endl;
}

bool readPacketHex(const std::string& packet_file, uint32_t file_offset,
                   uint32_t length, std::vector<unsigned char>& buffer)
{
    buffer.resize(length);
    FILE* file = fopen(packet_file.c_str(), "rb");
    if (!file) {
        std::cerr << "Failed to open file: " << packet_file << std::endl;
        buffer.clear();
        return false;
    }
    if (fseek(file, file_offset, SEEK_SET) != 0) {
        std::cerr << "Failed to seek to offset: " << file_offset << std::endl;
        fclose(file);
        buffer.clear();
        return false;
    }
    size_t bytesRead = fread(buffer.data(), 1, length, file);
    fclose(file);
    if (bytesRead != length) {
        std::cerr << "Failed to read data from file. Expected: " << length << ", got: " << bytesRead << std::endl;
        buffer.resize(bytesRead);
        return false;
    }
    return true;
}

int main()
{
    bool ret;
    // if you need to handle Chinese characters in the output, use setlocale
    setlocale(LC_ALL, "zh_CN.UTF-8"); 
    IP2RegionUtil ip2regionUtil;
    ip2regionUtil.init("third_library/ip2region/ip2region.xdb");
    std::string packet_file = "E:/Proj/nb_easy_tshark/pcap/10pkts.pcap";

    std::string read_pcap_cmd = "tshark \
            -r " + packet_file + "      \
            -T fields -e frame.number   \
            -e frame.time               \
            -e frame.cap_len            \
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
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        Packet packet;
        ret = parseLine(buffer, packet);
        if (!ret) {
            continue;
        }

        packet.file_offset = file_offset + sizeof(PacketHeader);
        file_offset += sizeof(PacketHeader) + packet.cap_len;
        vec_packets.push_back(packet);
    }
    _pclose(pipe);

    for (const auto& pkt : vec_packets) {
        printPacket(pkt);

        /* read hex data */
        std::vector<unsigned char> buffer;
        readPacketHex(packet_file, pkt.file_offset, pkt.cap_len, buffer);

        printf("Packet Hex: ");
        for (unsigned char byte : buffer) {
            printf("%02X ", byte);
        }
        printf("\n\n");
    }

    return 0;
}

