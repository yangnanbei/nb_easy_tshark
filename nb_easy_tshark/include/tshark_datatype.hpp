#pragma once
#include <iostream>
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <sys/types.h>
#include <Windows.h>

#ifdef _WIN32
typedef DWORD PID_T;
#else
typedef pid_t PID_T;
#endif /* _WIN32 */

struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

struct Packet {
    int frame_number;
    std::string time;
    std::string src_mac;
    std::string dst_mac;
    uint32_t cap_len;
    uint32_t len;
    std::string src_ip;
    std::string src_location;
    uint16_t src_port;
    std::string dst_ip;
    std::string dst_location;
    uint16_t dst_port;
    std::string protocol;
    std::string info;
    uint32_t file_offset;
};

/* e.g: 6. \Device\NPF_{FFCB4D95-E737-4DCA-B016-522C9BA641B5} (WLAN)
 * id:6
 * name:\Device\NPF_{FFCB4D95-E737-4DCA-B016-522C9BA641B5}
 * remark:WLAN
 */
struct AdapterInfo {
    int id;
    std::string name;
    std::string remark;
};

