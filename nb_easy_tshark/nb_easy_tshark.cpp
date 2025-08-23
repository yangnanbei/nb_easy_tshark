#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "loguru/loguru.hpp"
#include "TsharkManager.hpp"
#include "ip2region_util.h"

bool readPacketHex(const std::string& packet_file, uint32_t file_offset,
                   uint32_t length, std::vector<unsigned char>& buffer)
{
    buffer.resize(length);
    FILE* file = fopen(packet_file.c_str(), "rb");
    if (!file) {
        LOG_F(ERROR, "Failed to open file: %s", packet_file.c_str());
        buffer.clear();
        return false;
    }
    if (fseek(file, file_offset, SEEK_SET) != 0) {
        LOG_F(ERROR, "Failed to seek to offset %u in file: %s", file_offset, packet_file.c_str());
        fclose(file);
        buffer.clear();
        return false;
    }
    size_t bytesRead = fread(buffer.data(), 1, length, file);
    fclose(file);
    if (bytesRead != length) {
        LOG_F(ERROR, "Failed to read %u bytes from file: %s (read %zu bytes)", length, packet_file.c_str(), bytesRead);
        buffer.resize(bytesRead);
        return false;
    }
    return true;
}

int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "zh_CN.UTF-8"); 
    loguru::init(argc, argv);
    loguru::add_file("nb_easy_tshark.log", loguru::Append, loguru::Verbosity_MAX);

    std::string wrk_dir = "E:/Proj/nb_easy_tshark/nb_easy_tshark/nb_easy_tshark";

    TsharkManager tsharkManager(wrk_dir);
    tsharkManager.startCapture("WLAN");
    std::string input;
    while (1) {
        std::cout << "Enter 'q' to stop capturing and exit: ";
        std::cin >> input;
        if (input == "q" || input == "Q") {
            tsharkManager.stopCapture();
            break;
        }
    }

    tsharkManager.printAllPacket();

    /*
    std::vector<AdapterInfo> adapters = tsharkManager.getNetWorkAdapters();
    for (auto item: adapters) {
        LOG_F(INFO, "Adapter ID: %d, Name: %s, Remark: %s", item.id, item.name.c_str(), item.remark.c_str());
    }
    */

    return 0;
}

