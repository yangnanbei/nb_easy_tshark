#include "TsharkManager.hpp"
#include "ProcessUtil.hpp"
#include <loguru/loguru.hpp>

TsharkManager::TsharkManager(std::string workDir) {
    this->tsharkPath = "tshark"; /* I currently set it to my sys env */
    std::string xdbFilePath = workDir + "/third_library/ip2region/ip2region.xdb";
    ip2regionUtil.init(xdbFilePath);
}

TsharkManager::~TsharkManager() {
    ip2regionUtil.uninit();
}

bool TsharkManager::parseLine(std::string line, std::shared_ptr<Packet> packet) {
    if (line.back() == '\n') {
        line.pop_back();
    }
    std::stringstream ss(line);
    std::vector<std::string> fields;

    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); 

    /*
     * fields：
     * 0. frame.number
     * 1. frame.time_epoch
     * 2. frame.len
     * 3. frame.cap_len
     * 4. eth.src
     * 5. eth.dst
     * 6. ip.src
     * 7. ipv6.src
     * 8. ip.dst
     * 9. ipv6.dst
     * 10.tcp.srcport
     * 11.udp.srcport
     * 12.tcp.dstport
     * 13.udp.dstport
     * 14._ws.col.Protocol
     * 15._ws.col.Info
     */  

    if (fields.size() >= 16) {
        packet->frame_number = std::stoi(fields[0]);
        packet->time = fields[1];
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[8] : fields[8];
        if (!fields[10].empty() || !fields[11].empty()) {
            packet->src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }

        if (!fields[12].empty() || !fields[13].empty()) {
            packet->dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->protocol = fields[14];
        packet->info = fields[15];
    }
    else {
        if (line == "Active code page: 65001") {
            /* Ignore this line, it's my local env setup */
        }
        else {
            std::cerr << "Error: Not enough fields in line." << std::endl;
            return false;
        }
    }

    return true;
}

bool TsharkManager::analysisFile(std::string filePath) {

    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-r", filePath             ,
        "-T", "fields"             ,
        "-e", "frame.number"       ,
        "-e", "frame.time_epoch"   ,
        "-e", "frame.len"          ,
        "-e", "frame.cap_len"      ,
        "-e", "eth.src"            ,
        "-e", "eth.dst"            ,
        "-e", "ip.src"             ,
        "-e", "ipv6.src"           ,
        "-e", "ip.dst"             ,
        "-e", "ipv6.dst"           ,
        "-e", "tcp.srcport"        ,
        "-e", "udp.srcport"        ,
        "-e", "tcp.dstport"        ,
        "-e", "udp.dstport"        ,
        "-e", "_ws.col.Protocol"   ,
        "-e", "_ws.col.Info"       ,
    };

    std::string command;
    for (auto arg: tsharkArgs) {
        command += arg + " ";
    }

    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Fail to read pcap by tshark!" << std::endl;
        return false;
    }


    char buffer[4096];
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet)) {
            LOG_F(ERROR, "Error parsing line: %s\n", buffer);
            assert(false);
        }

        /* upadate offset */
        packet->file_offset = file_offset + sizeof(PacketHeader);
        file_offset += sizeof(PacketHeader) + packet->cap_len;

        /* get ip location */
        packet->src_location = ip2regionUtil.getIpLocation(packet->src_ip);
        packet->dst_location = ip2regionUtil.getIpLocation(packet->dst_ip);

        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }
    _pclose(pipe);

    currentFilePath = filePath;

    return true;
}

void TsharkManager::printAllPacket() {

    for (const auto& pair : allPackets) {
        std::shared_ptr<Packet> packet = pair.second;

        /* build json obj */
        rapidjson::Document pktObj;
        rapidjson::Document::AllocatorType& allocator = pktObj.GetAllocator();

        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->frame_number, allocator);
        pktObj.AddMember("timestamp", rapidjson::Value(packet->time.c_str(), allocator), allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(IP2RegionUtil::getIpLocation(packet->src_ip).c_str(), allocator), allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(IP2RegionUtil::getIpLocation(packet->dst_ip).c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->src_port, allocator);
        pktObj.AddMember("dst_port", packet->dst_port, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->file_offset, allocator);
        pktObj.AddMember("caplen", packet->cap_len, allocator);
        pktObj.AddMember("caplen", packet->len, allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        LOG_F(INFO, "Packet %d: %s", packet->frame_number, buffer.GetString());
    }
}

bool TsharkManager::getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data) {
    std::vector<unsigned char> buffer;
    // todo: implement readPacketHex
    return true;
}


std::vector<AdapterInfo> TsharkManager::getNetWorkAdapters() {
    /* need filter some special interface which are not real network adapter */
    std::set<std::string> specialInterface = {
        "ciscodump",
        "etwdump",
        "sshdump.exe",
        "udpdump",
        "wifidump.exe",
    };

    /* real world interface */
    std::vector<AdapterInfo> interfaces;

    char buffer[512]{};
    std::string result;

    std::string command = tsharkPath + " -D";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("Failed to run command: " + command);
    }

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }

    /* get name and remark
     * e.g: 6. \Device\NPF_{FFCB4D95-E737-4DCA-B016-522C9BA641B5} (WLAN)
     * id:6
     * name:\Device\NPF_{FFCB4D95-E737-4DCA-B016-522C9BA641B5}
     * remark:WLAN
     */
    std::istringstream stream(result);
    std::string line;
    int id = 0;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        size_t start = line.find(' ');
        if (start != std::string::npos) {
            size_t end = line.find(' ', start + 1);
            std::string ifName;
            if (end != std::string::npos) {
                 ifName = line.substr(start + 1, end - start - 1);
            }
            else {
                 ifName = line.substr(start + 1);
            }
            
            if (specialInterface.find(ifName) != specialInterface.end()) {
                continue;
            }

            AdapterInfo adapter;
            adapter.id = ++id;
            adapter.name = ifName;

            size_t bracketStart = line.find('(');
            size_t bracketEnd   = line.rfind(')'); /* on I'm fucking genius */
            if (bracketStart != std::string::npos && bracketEnd != std::string::npos && bracketEnd > bracketStart) {
                adapter.remark = line.substr(bracketStart + 1, bracketEnd - bracketStart - 1);
            } else {
                adapter.remark = "Unknown";
            }

            interfaces.push_back(adapter);
        }
    }

    _pclose(pipe);
    return interfaces;
}

bool TsharkManager::startCapture(std::string adapterName) {
    LOG_F(INFO, "start to capture, adapterName %s", adapterName.c_str());
    stopFlag = false;
    captureWorkerThread =  std::make_shared<std::thread>(&TsharkManager::captureWorkerThreadEntry,
        this, "\"" + adapterName + "\"");

    return true;
}

void TsharkManager::captureWorkerThreadEntry(std::string adapterName) {
    std::string captureFile = "capture.pcap";

    std::vector<std::string> tsharkArgs = {
        tsharkPath,
        "-i", adapterName          ,
        "-w", captureFile          , /* write to captureFile */
        "-F", "pcap"               , /* save file as pcap format */
        "-T", "fields"             ,
        "-e", "frame.number"       ,
        "-e", "frame.time_epoch"   ,
        "-e", "frame.len"          ,
        "-e", "frame.cap_len"      ,
        "-e", "eth.src"            ,
        "-e", "eth.dst"            ,
        "-e", "ip.src"             ,
        "-e", "ipv6.src"           ,
        "-e", "ip.dst"             ,
        "-e", "ipv6.dst"           ,
        "-e", "tcp.srcport"        ,
        "-e", "udp.srcport"        ,
        "-e", "tcp.dstport"        ,
        "-e", "udp.dstport"        ,
        "-e", "_ws.col.Protocol"   ,
        "-e", "_ws.col.Info"       ,
    };

    std::string command;
    for (auto arg : tsharkArgs) {
        command += arg + " ";
    }

    //FILE* pipe = _popen(command.c_str(), "r");
    todo: FILE* pipe = ProcessUtil::PopenEx(command.c_str(), &captureTsharkPid);
    if (!pipe) {
        std::cerr << "Fail to run tshark!" << std::endl;
        return;
    }

    char buffer[4096];
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr && !stopFlag) {
        std::string line = buffer;
        if (line.find("Capturing on") != std::string::npos) {
            continue;
        }

        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parseLine(buffer, packet)) {
            LOG_F(ERROR, "Error parsing line: %s\n", buffer);
            assert(false);
        }

        /* upadate offset */
        packet->file_offset = file_offset + sizeof(PacketHeader);
        file_offset += sizeof(PacketHeader) + packet->cap_len;

        /* get ip location */
        packet->src_location = ip2regionUtil.getIpLocation(packet->src_ip);
        packet->dst_location = ip2regionUtil.getIpLocation(packet->dst_ip);

        allPackets.insert(std::make_pair<>(packet->frame_number, packet));
    }
    _pclose(pipe);

    currentFilePath = captureFile;

    return;
}

bool TsharkManager::stopCapture() {
    LOG_F(INFO, "now stop capture pcap");
    stopFlag = true;
    ProcessUtil::Kill(captureTsharkPid);
    captureWorkerThread->join();

    return true;
}

void TsharkManager::startMonitorAdaptersFlowTrend() {
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    adapterFlowTrendMonitorStartTime = std::time(nullptr);

    /* get adapter list */
    std::vector<AdapterInfo> adapterList = getNetWorkAdapters();

    /* start thread for every single adapter */
    for (auto adapter : adapterList) {
        adapterFlowTrendMonitorMap.insert(std::make_pair<>(adapter.name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = adapterFlowTrendMonitorMap.at(adapter.name);
        
        monitorInfo.monitorThread = std::make_shared<std::thread>(
            &TsharkManager::adapterFlowTrendMonitorThreadEntry,
            this,
            adapter.name);

        if (monitorInfo.monitorThread == nullptr) {
            LOG_F(ERROR, "Create monitor threads fail! adapter name %s", adapter.name.c_str())l
        }
        else {
            LOG_F(INFO, "Create monitor threads success! adapter name %s, monitorThread %p", adapter.name.c_str(),
                monitorInfo.monitorThread.get());
        }
    }

}

void TsharkManager::adapterFlowTrendMonitorThreadEntry(std::string adapterName) {
    adapterFlowTrendMapLock.lock();

    if (adapterFlowTrendMonitorMap.find(adapterName) == adapterFlowTrendMonitorMap.end()) {
        adapterFlowTrendMapLock.unlock();
        return;
    }

    adapterFlowTrendMapLock.unlock();

    char buffer[1024]{};
    /* map: pair of timestamp and length */
    std::map<long, long>& trafficPerSecond = adapterFlowTrendMonitorMap.at(adapterName).flowTrendData;

    std::string command = tsharkPath + " -i \"" + adapterName + "\" -T fields -e frame.time_epoch -e frame.len";
    LOG_F(INFO, "Start monitor adapter %s", adapterName.c_str());

    PID_T tsharkPid = 0;
    FILE* pipe = ProcessUtil::PopenEx(command.c_str(), &tsharkPid);
    if (!pipe) {
        throw std::runtime_error("Failed to run command: " + command);
    }

    /* save pipe */
    adapterFlowTrendMapLock.lock();
    adapterFlowTrendMonitorMap[adapterName].monitorTsharkPipe = pipe;
    adapterFlowTrendMonitorMap[adapterName].tsharkPid = tsharkPid;
    adapterFlowTrendMapLock.unlock();

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line = buffer;
        std::istringstream iss(line);
        std::string timestampStr, lengthStr;

        if (line.find("Capturing on") != std::string::npos ||
            line.find("captured") != std::string::npos) {
            continue;
        }

        /* now we need to parse the timestamp and length for every line */
        if (!(iss >> timestampStr >> lengthStr)) {
            continue;
        }

        try {
            long timestamp = static_cast<long>(std::stol(timestampStr));
            long packetLength = static_cast<long>(std::stol(lengthStr));
            /* iterate to add the Bytes of every second */
            trafficPerSecond[timestamp] += packetLength;

            /* we don't need to save all the pair<timestamp, bytes> data,
               the recent 300s is defiently enough */
            while (trafficPerSecond.size() > 300) {
                auto it = trafficPerSecond.begin();
                LOG_F(INFO, "Erase old traffic data, timestamp %ld, bytes %ld", it->first, it->second);
                trafficPerSecond.erase(it);
            }
        }
        catch (const std::exception& e) {
            LOG_F(ERROR, "Exception parsing tshark output: %s", line.c_str());
            continue;
        }
    }
    LOG_F(INFO, "Monitor adapter %s finished!", adapterName.c_str());
}

void TsharkManager::stopMonitorAdaptersFlowTrend() {
    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);
    for (auto& adapterPipePair : adapterFlowTrendMonitorMap) {
    }
}
void TsharkManager::stopMonitorAdaptersFlowTrend() {

    std::unique_lock<std::recursive_mutex> lock(adapterFlowTrendMapLock);

    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {
        ProcessUtil::Kill(adapterPipePair.second.tsharkPid);
    }

    for (auto adapterPipePair : adapterFlowTrendMonitorMap) {

        _pclose(adapterPipePair.second.monitorTsharkPipe);

        adapterPipePair.second.monitorThread->join();

        LOG_F(INFO, "adapter：%s monitr stop!", adapterPipePair.first.c_str());
    }

    adapterFlowTrendMonitorMap.clear();
}
