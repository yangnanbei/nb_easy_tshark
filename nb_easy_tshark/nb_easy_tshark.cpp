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

    tsharkManager.startMonitorAdaptersFlowTrend();

    // 睡眠10秒，等待监控网卡数据
    std::this_thread::sleep_for(std::chrono::seconds(10));

    std::map<std::string, std::map<long, long>> trendData;
    tsharkManager.getAdaptersFlowTrendData(trendData);

    tsharkManager.stopMonitorAdaptersFlowTrend();

    rapidjson::Document resDoc;
    rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
    resDoc.SetObject();
    rapidjson::Value dataObject(rapidjson::kObjectType);
    for (const auto& adaptorItem : trendData) {
        rapidjson::Value adaptorDataList(rapidjson::kArrayType);
        for (const auto& timeItem : adaptorItem.second) {
            rapidjson::Value timeObj(rapidjson::kObjectType);
            timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
            timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
            adaptorDataList.PushBack(timeObj, allocator);
        }

        dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
    }

    resDoc.AddMember("data", dataObject, allocator);

    // 序列化为 JSON 字符串
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    resDoc.Accept(writer);

    LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());

    return 0;

#if 0
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
#endif 
}

