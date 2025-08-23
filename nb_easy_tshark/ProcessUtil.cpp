#include "ProcessUtil.hpp"
#include <io.h>
#include <fcntl.h>
#include <winnt.h>

FILE* ProcessUtil::PopenEx(std::string command, PID_T* pidOut) {
#if defined(__unix__) || defined(__APPLE__)
   int pipefd[2] = { 0 }; /* [0]:reader, [1]:writer */
   FILE* pipeFp = nullptr;

   if (pipe(pipefd) == -1) {
       perror("pipe");
       return nullptr;
   }

   pid_t pid = fork();
   if (pid == -1) {
       perror("fork");
       close(pipefd[0]);
       close(pipefd[1]);
       return nullptr;
   }

   if (pid == 0) {
       /* chile process */
       close(pipefd[0]);  /* close reader */
       dup2(pipefd[1], STDOUT_FILENO); /* send stdout to pipe* /
       dup2(pipefd[1], STDERR_FILENO); /* send stderr to pipe* /
       close(pipefd[1]);

       execl("/bin/sh", "sh", "-c", command.c_str(), NULL);
       _exit(1);
   }

   /* father process read from pipe, close writer and read reader */
       close(pipefd[1]);
       pipeFp = fdopen(pipefd[0], "r");

       if (pidOut) {
           *pidOut = pid;
       }

       return pipeFp;
   }
#elif defined (_WIN32)
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES saAttr;
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    FILE* pipeFp = nullptr;

    /* set safe attr, allow pipe handle inherance */
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
        perror("CreatePipe");
        return nullptr;
    }

    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        perror("SetHandleInformation");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return nullptr;
    }

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = hWritePipe;
    siStartInfo.hStdOutput = hWritePipe;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    /* create the child process */
    if (!CreateProcess(
        nullptr,                        // No module name (use command line)
        (LPWSTR)command.data(),          // Command line
        nullptr,                        // Process handle not inheritable
        nullptr,                        // Thread handle not inheritable
        TRUE,                           // Set handle inheritance
        CREATE_NO_WINDOW,               // No window
        nullptr,                        // Use parent's environment block
        nullptr,                        // Use parent's starting directory 
        &siStartInfo,                   // Pointer to STARTUPINFO structure
        &piProcInfo                     // Pointer to PROCESS_INFORMATION structure
    )) {
        perror("CreateProcess");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return nullptr;
    }

    CloseHandle(hWritePipe);

    if (pidOut) {
        *pidOut = piProcInfo.dwProcessId;
    }

    pipeFp = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(hReadPipe), _O_RDONLY), "r");
    if (!pipeFp) {
        CloseHandle(hReadPipe);
    }

    // 关闭进程句柄（不需要等待子进程）
    CloseHandle(piProcInfo.hProcess);
    CloseHandle(piProcInfo.hThread);

    return pipeFp;
}
#endif /* elif defined(_win32) */

int ProcessUtil::Kill(PID_T pid) {
#if defined(__unix__) || defined(__APPLE__)
    return kill(pid, SIGTERM);
#elif defined(_WIN32)
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == nullptr) {
        std::cout << "Failed to open process with PID " << pid << ", error: " << GetLastError() << std::endl;
        return -1;
    }

    if (!TerminateProcess(hProcess, 0)) {
        std::cout << "Failed to terminate process with PID " << pid << ", error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    CloseHandle(hProcess);
    return 0;
#endif
}
