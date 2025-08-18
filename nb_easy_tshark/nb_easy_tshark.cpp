#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "TsharkManager.hpp"
#include "ip2region_util.h"

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
    std::string packet_file = "E:/Proj/nb_easy_tshark/pcap/10pkts.pcap";
    std::string wrk_dir = "E:/Proj/nb_easy_tshark/nb_easy_tshark/nb_easy_tshark";

    TsharkManager tsharkManager(wrk_dir);
    tsharkManager.analysisFile(packet_file);

    tsharkManager.printAllPacket();

    return 0;
}

