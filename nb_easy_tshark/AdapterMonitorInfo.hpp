#pragma once
#include "tshark_datatype.hpp"
#include <map>
#include <thread>

class AdapterMonitorInfo
{
public:
    AdapterMonitorInfo() {
        monitorTsharkPipe = nullptr;
        tsharkPid = 0;
    }

    std::string adapterName;
    std::map<long, long> flowTrendData;
    std::shared_ptr<std::thread> monitorThread;
    FILE* monitorTsharkPipe = nullptr;
    PID_T tsharkPid;
};

