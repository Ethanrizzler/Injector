#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <iostream>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

#define PROCESS_ALL_ACCESS 0x1F0FFF
#define TH32CS_SNAPPROCESS 0x00000002
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_READ 0x20
#define WH_GETMESSAGE 3
#define WM_NULL 0x0000
DWORD GetProcessId(const std::wstring& processName)
{
    DWORD ret = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &entry))
        {
            do
            {
                if (processName.compare(entry.szExeFile) == 0)
                {
                    ret = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return ret;
}

bool InjectDLL(HANDLE processHandle, const std::string& dllPath) {
    LPVOID allocMem = VirtualAllocEx(processHandle, NULL, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMem) {
        std::cerr << "[!] Failed to allocate memory in target process." << std::endl;
        return false;
    }

    if (!WriteProcessMemory(processHandle, allocMem, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        std::cerr << "[!] Failed to write DLL path to target process memory." << std::endl;
        return false;
    }

    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (!hKernel32) {
        std::cerr << "[!] Failed to get handle for kernel32.dll." << std::endl;
        return false;
    }

    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!loadLibraryAddr) {
        std::cerr << "[!] Failed to get address of LoadLibraryA." << std::endl;
        return false;
    }

    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, loadLibraryAddr, allocMem, 0, NULL);
    if (!remoteThread) {
        std::cerr << "[!] Failed to create remote thread." << std::endl;
        return false;
    }

    WaitForSingleObject(remoteThread, INFINITE);
    CloseHandle(remoteThread);
    return true;
}

int main()
{
    std::cout << "[+] Waiting for Roblox process..." << std::endl;

    DWORD processId;
    while (!(processId = GetProcessId(L"RobloxPlayerBeta.exe"))) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "[+] PID: " << processId << std::endl;

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle) {
        std::cerr << "[!] Failed to open Roblox process." << std::endl;
        return -1;
    }

    std::string dllPath = "C:\\Users\\Bobby\\source\\repos\\ModuleLoader\\x64\\Debug\\ModuleX012.dll";

    if (InjectDLL(processHandle, dllPath)) {
        std::cout << "[+] Module Loaded" << std::endl;
    }
    else {
        std::cerr << "[!] DLL injection failed." << std::endl;
    }

    CloseHandle(processHandle);
    return 0;
}
