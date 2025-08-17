#include <string>
#include <iostream>
#include "../third_library/ip2region/xdb_search.h"
#include "ip2region_util.h"

/* g++ -std=c++14 .\03_ip2region_class.cpp
    ..\third_library\ip2region\xdb_search.cc
    ..\ip2region_util.cpp -o .\ip2region_test2.exe -lws2_32
    -I..\include\ -I..\third_library\*/

int test3_main() {
    IP2RegionUtil ip2regionUtil;
    ip2regionUtil.init("../third_library/ip2region/ip2region.xdb");

    std::string ip = "211.21.92.114";
    std::string location = ip2regionUtil.getIpLocation(ip);

    std::cout << ip << ": " << location << std::endl;

    return 0;
}
