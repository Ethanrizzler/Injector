#include <windows.h>
#include <iostream>


DWORD WINAPI uhminject(LPVOID param) {
    MessageBoxA(NULL, "Injected", "Module", MB_OK | MB_ICONINFORMATION);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, uhminject, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
