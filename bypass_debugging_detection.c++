#include <Windows.h>
#include <winternl.h>

HMODULE myhmod;

DWORD WINAPI MainThread(LPVOID lpReserved) {
    while (true) {
        Sleep(10);
#ifdef _WIN64
        PTEB teb = (PTEB)__readgsqword(0x30);
        PPEB peb = (PPEB)teb->ProcessEnvironmentBlock;
        peb->BeingDebugged = 0x0;
#else
        PTEB teb = (PTEB)__readfsdword(0x18);
        PPEB peb = (PPEB)teb->ProcessEnvironmentBlock;
        peb->BeingDebugged = 0x0;
#endif
    }
    return TRUE;
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        myhmod = hMod;
        CreateThread(nullptr, 0, MainThread, hMod, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
