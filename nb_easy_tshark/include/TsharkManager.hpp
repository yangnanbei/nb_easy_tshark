#pragma once
#include "tshark_datatype.hpp"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"
#include "AdapterMonitorInfo.hpp"

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <set>
#include <thread>
#include <map>
#include <mutex>

class TsharkManager
{
public:
    TsharkManager(std::string workDir);
    ~TsharkManager();

    bool analysisFile(std::string filePath);

    void printAllPacket();

    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

    std::vector<AdapterInfo> getNetWorkAdapters();

    bool startCapture(std::string adapterName);

    bool stopCapture();

    /* monitor the adapter traffic */
    void startMonitorAdaptersFlowTrend();
    void stopMonitorAdaptersFlowTrend();

private:
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

    void captureWorkerThreadEntry(std::string adapterName);

    void adapterFlowTrendMonitorThreadEntry(std::string adapterName);

    std::shared_ptr<std::thread> captureWorkerThread;

private:
    std::string tsharkPath;
    std::string currentFilePath;
    bool stopFlag = false;              /* stop capture process */
    PID_T captureTsharkPid;
    time_t adapterFlowTrendMonitorStartTime;

    IP2RegionUtil ip2regionUtil;

    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
    /* monitor the flow trend, map <adapter name, adapter info> */
    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

    /* protect trend map */
    std::recursive_mutex adapterFlowTrendMapLock;
};

