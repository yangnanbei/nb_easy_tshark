#include <iostream>
#include <cstdio>

int main()
{
    const char* read_pcap_cmd = "tshark -r E:/Proj/nb_easy_tshark/pcap/capture.pcap";
    std::cerr << "cmd is " << read_pcap_cmd << std::endl;
    FILE *pipe = _popen(read_pcap_cmd, "r");
    if (!pipe) {
        std::cerr << "Fail to read pcap by tshark!" << std::endl;
        return 1;
    }

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
    }
    std::cout << std::endl;
    _pclose(pipe);
    return 0;
}

