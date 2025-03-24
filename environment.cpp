#include <windows.h>
#include "pch.h"
// i didnt fix the correct call back
// dll U can modfiy anything u want!
extern "C" __declspec(dllexport) LRESULT CALLBACK callback(int nCode, WPARAM wParam, LPARAM lParam) {

    MessageBoxA(NULL, "[+] Callback function triggered", "DLL Hook", MB_OK);

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "[+] DLL Injected!", "DLL Injection", MB_OK);
    }
    return TRUE;
}
