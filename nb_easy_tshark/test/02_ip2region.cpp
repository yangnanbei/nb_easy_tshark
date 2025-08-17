#include "../third_library/ip2region/xdb_search.h"
#include <string>
#include <iostream>

/* compile:  g++ -std=c++14 .\02_ip2region.cpp 
   ..\third_library\ip2region\xdb_search.cc -o ip2region_test.exe -lws2_32 */

int test2_main() {
    xdb_search_t searcher("../third_library/ip2region/ip2region.xdb");
    searcher.init_content();

    std::string ip = "211.21.92.114";
    std::string location = searcher.search(ip);

    std::cout << ip << ": " << location << std::endl;

    return 0;
}
