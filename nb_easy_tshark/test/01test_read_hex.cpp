#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>

struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
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

/* change to main to test */
int test_main() {
    std::ifstream file("E:/Proj/nb_easy_tshark/pcap/10pkts.pcap", std::ios::binary);
    if (!file) {
        std::cerr << "无法打开文件！\n";
        return 0;
    }

    /* read pcap header */
    PcapHeader pcapHeader;
    file.read(reinterpret_cast<char*>(&pcapHeader), sizeof(PcapHeader));

    while (file) {

        /* read packet header */
        PacketHeader packetHeader;
        file.read(reinterpret_cast<char*>(&packetHeader), sizeof(PacketHeader));

        if (!file) break;

        /* read pcap data */
        std::vector<unsigned char> data(packetHeader.caplen);
        file.read(reinterpret_cast<char*>(data.data()), packetHeader.caplen);

        printf("packet[time：%d  len：%d]：", packetHeader.ts_sec, packetHeader.caplen);
        for (unsigned char byte : data) {
            printf("%02X ", byte);
        }
        std::cout << "\n";
    }
    file.close();
    return 0;
}
