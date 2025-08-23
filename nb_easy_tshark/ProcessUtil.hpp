#pragma once
#include "tshark_datatype.hpp"
class ProcessUtil
{
public:
    static FILE* PopenEx(std::string command, PID_T* pidOut = nullptr);

    static int Kill(PID_T pid);
};

