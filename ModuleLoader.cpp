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

int main()
{
    SetConsoleTitle(L"Injector");

    std::cout << "Waiting for Roblox process..." << std::endl;

    HWND windowHandle;
    while (true)
    {
        windowHandle = FindWindow(NULL, L"Roblox");  
        if (IsWindowVisible(windowHandle))
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    system("cls");

    DWORD processId = GetProcessId(L"RobloxPlayerBeta.exe");
    if (processId == 0)
    {
        std::cout << "Failed to find Roblox process." << std::endl;
        return -1;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle)
    {
        std::cout << "Failed to open process." << std::endl;
        return -1;
    }

    // PATCH WinVerifyTrust  
    HMODULE wintrustModule = LoadLibraryA("wintrust.dll");
    FARPROC _winVerifyTrust = GetProcAddress(wintrustModule, "WinVerifyTrust");

    BYTE payload[] = { 0x48, 0x31, 0xC0, 0x59, 0xFF, 0xE1 }; 

    DWORD oldProtect;
    if (!VirtualProtectEx(processHandle, _winVerifyTrust, sizeof(payload), PAGE_EXECUTE_READWRITE, &oldProtect))
        std::cout << "Failed to protect WinVerifyTrust." << std::endl;

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(processHandle, _winVerifyTrust, payload, sizeof(payload), &bytesWritten))
        std::cout << "Failed to patch WinVerifyTrust." << std::endl;

    VirtualProtectEx(processHandle, _winVerifyTrust, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect);

    //  DLL INJECTION THROUGH LoadLibraryA  
    if (GetFileAttributesA("Module.dll") == INVALID_FILE_ATTRIBUTES)
    {
        std::cout << "DLL not found." << std::endl;
        return -1;
    }

    LPVOID allocatedMem = VirtualAllocEx(processHandle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocatedMem)
    {
        std::cout << "Failed to allocate memory in target process." << std::endl;
        return -1;
    }

    if (!WriteProcessMemory(processHandle, allocatedMem, "nyx.dll", strlen("nyx.dll") + 1, NULL))
    {
        std::cout << "Failed to write DLL path to process memory." << std::endl;
        return -1;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr)
    {
        std::cout << "Failed to get LoadLibraryA address." << std::endl;
        return -1;
    }

    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMem, 0, NULL);
    if (!remoteThread)
    {
        std::cout << "Failed to create remote thread." << std::endl;
        return -1;
    }

    std::cout << "Module Attached Successfully." << std::endl;
    
    CloseHandle(remoteThread);
    CloseHandle(processHandle);

    std::this_thread::sleep_for(std::chrono::hours(999));  
    return 0;
}
