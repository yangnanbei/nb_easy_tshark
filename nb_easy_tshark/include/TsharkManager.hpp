#pragma once
#include "tshark_datatype.hpp"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <unordered_map>

class TsharkManager
{
public:
    TsharkManager(std::string workDir);
    ~TsharkManager();

    bool analysisFile(std::string filePath);

    void printAllPacket();

    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

private:
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

private:
    std::string tsharkPath;
    std::string currentFilePath;

    IP2RegionUtil ip2regionUtil;

    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;
};

