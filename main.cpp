#include <Windows.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include"detours.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Ws2_32.lib")
#define WSAAPI                  FAR PASCAL

HMODULE myhmod;
DWORD pid = 0;

void get_proc_id(LPCWSTR window_title, DWORD& process_id)
{
    GetWindowThreadProcessId(FindWindow(NULL, window_title), &process_id);
}

// Function to convert UNICODE_STRING to std::wstring
std::wstring UnicodeStringToWString(const UNICODE_STRING& unicodeString) {
    return std::wstring(unicodeString.Buffer, unicodeString.Length / sizeof(WCHAR));
}

bool InitializeSymbolHandler() {
    if (!SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
        std::cerr << "Failed to initialize symbol handler! Error code: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

void CleanupSymbolHandler() {
    SymCleanup(GetCurrentProcess());
}

bool LoadModuleSymbols(const char* moduleName) {
    DWORD64 moduleBase = SymLoadModuleEx(GetCurrentProcess(), NULL, moduleName, NULL, 0, 0, NULL, 0);
    if (moduleBase == 0) {
        std::cerr << "Failed to load module symbols! Error code: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

bool GetFunctionNameFromAddress(PVOID address, std::string& functionName) {
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO symbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
    symbol->MaxNameLen = MAX_SYM_NAME;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

    DWORD64 displacement = 0;
    if (SymFromAddr(GetCurrentProcess(), reinterpret_cast<DWORD64>(address), &displacement, symbol)) {
        functionName = symbol->Name;
        return true;
    }
    else {
        std::cerr << "Failed to get function name from address! Error code: " << GetLastError() << std::endl;
        return false;
    }
}

bool GetThreadStartAddress(DWORD dwThreadId, LPVOID* lpStartAddress) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
    if (hThread == NULL) {
        std::cerr << "Failed to open thread! Error code: " << GetLastError() << std::endl;
        return false;
    }

    SuspendThread(hThread);

    CONTEXT context;
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &context)) {
        std::cerr << "Failed to get thread context! Error code: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        return false;
    }

#ifdef _WIN64
    * lpStartAddress = reinterpret_cast<LPVOID>(context.Rip);
#else
    * lpStartAddress = reinterpret_cast<LPVOID>(context.Eip);
#endif

    ResumeThread(hThread);
    CloseHandle(hThread);

    return true;
}

void SandboxThread(DWORD threadId) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    if (hThread == NULL) {
        std::cerr << "Failed to open thread! Error code: " << GetLastError() << std::endl;
        return;
    }

    SuspendThread(hThread);

    PVOID startAddress;
    if (GetThreadStartAddress(threadId, &startAddress)) {
        std::cout << "Sandboxing thread with start address: " << startAddress << std::endl;

        PTEB teb = (PTEB)__readgsqword(0x30);
        PPEB peb = (PPEB)teb->ProcessEnvironmentBlock;
        peb->BeingDebugged = 0x0;

        printf("peb address : %p \n", peb);
        printf("Being debugged : 0x%x \n", peb->BeingDebugged);



        // Get the PEB_LDR_DATA structure
        PPEB_LDR_DATA ldr = peb->Ldr;

        // Iterate through the InLoadOrderModuleList
        PLIST_ENTRY moduleList = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY ListEntry = moduleList->Flink;
        std::wstring ntdllPath = L"C:\\Windows\\System32\\ntdll.dll";

        while (ListEntry != moduleList) {
            PLDR_DATA_TABLE_ENTRY dataTableEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            
            std::wstring fullDllName = UnicodeStringToWString(dataTableEntry->FullDllName);

            if (fullDllName == ntdllPath) {
                std::wcout << L"DllBase: " << dataTableEntry->DllBase << std::endl;//0x74C50000 for exemple
                DetourRestoreAfterWith();
                DetourTransactionBegin();
                DetourUpdateThread(hThread);

                DetourAttach(&(PVOID&)dataTableEntry->DllBase, (PVOID)dataTableEntry->DllBase);
                DetourTransactionCommit();
            }

            // Move to the next module
            ListEntry = ListEntry->Flink;
        }
       
    }

    ResumeThread(hThread);
    CloseHandle(hThread);
}

DWORD WINAPI MainThread(LPVOID lpReserved) {
    DWORD original_protection;
    VirtualProtect(&FreeConsole, sizeof(uint8_t), PAGE_EXECUTE_READWRITE, &original_protection);
    *(uint8_t*)(&FreeConsole) = 0xC3;
    VirtualProtect(&FreeConsole, sizeof(uint8_t), original_protection, NULL);
    AllocConsole();
    FILE* stream;
    freopen_s(&stream, "CONIN$", "r", stdin);
    freopen_s(&stream, "CONOUT$", "w", stdout);

    InitializeSymbolHandler();
    if (!LoadModuleSymbols("C:\\Windows\\System32\\ntdll.dll")) {
        CleanupSymbolHandler();
        return 1;
    }

    pid = GetCurrentProcessId();
    std::cout << "Process ID: " << pid << std::endl;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    Thread32First(hSnapshot, &te32);
    while (Thread32Next(hSnapshot, &te32)) {
        if (te32.th32OwnerProcessID == pid) {
            std::cout << "Thread ID: " << te32.th32ThreadID << std::endl;

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                PVOID startAddress;
                if (GetThreadStartAddress(te32.th32ThreadID, &startAddress)) {
                    std::cout << "Thread Base Address: " << startAddress << std::endl;

                    SandboxThread(te32.th32ThreadID);

                    std::string functionName;
                    DWORD temp = reinterpret_cast<DWORD>(startAddress);
                    temp -= 0xC;
                    printf("Temp : 0x%x \n", temp);
                    PVOID New = reinterpret_cast<PVOID>(temp);
                    if (GetFunctionNameFromAddress(New, functionName)) {
                        std::cout << "Function name: " << functionName << std::endl;
                    }

                    std::cout << "=============================================" << std::endl;
                }
            }
        }
    }
    CloseHandle(hSnapshot);

    CleanupSymbolHandler();
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
