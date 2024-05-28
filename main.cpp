#include "includes.h"
#include"detours.h"
#include<string>
#include<iomanip>
#include <tlhelp32.h>
#include<iostream>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Ws2_32.lib")
#define WSAAPI                  FAR PASCAL

//Constant
HMODULE myhmod;
FILE* pFile = nullptr;
HWND hwndOutput = nullptr;
HWND hwndInput = nullptr;
HWND hwndInputLen = nullptr;
#define WSAEVENT HANDLE
struct sockaddr_in clientService;

//backup in case
SOCKET ConnectSocket = INVALID_SOCKET;

//Proto functions
typedef int (WINAPI* SendPtr)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI* WSASendPtr)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, LPDWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI* ConnectCustom)(SOCKET s, const SOCKADDR* sAddr, int nameLen);
typedef int (WINAPI* SendToCustom)(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int ToLen);
typedef int (WINAPI* CustomGetaddrinfo)(PCSTR Host, PCSTR port, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

//Lib
HMODULE hLib = LoadLibrary("WS2_32.dll");
HMODULE hNtdll = GetModuleHandle("ntdll.dll");

//get the internal function 
SendPtr pSend = (SendPtr)GetProcAddress(hLib, "send");
ConnectCustom pConnect = (ConnectCustom)GetProcAddress(hLib, "connect");
WSASendPtr pWsaSend = (WSASendPtr)GetProcAddress(hLib, "WSASend");
SendToCustom pSendTo = (SendToCustom)GetProcAddress(hLib, "sendto");
CustomGetaddrinfo pGetAddrInfo = (CustomGetaddrinfo)GetProcAddress(hLib, "getaddrinfo");
NtCreateThreadEx_t OriginalNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");

int SERVER_IP;
int PORT;

int TO_SERVER_IP;
int TO_PORT;

PCSTR WSA_TO_SERVER_IP = "";
int WSA_TO_PORT;

static int FilterPacketSize = 200; //default size x)

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

Present oPresent;
HWND window = NULL;
WNDPROC oWndProc;
ID3D11Device* pDevice = NULL;
ID3D11DeviceContext* pContext = NULL;
ID3D11RenderTargetView* mainRenderTargetView;

// Input and Output buffers
static char Input[10000] = "Enter your packet here :p";;
static char Output[10000] = "Packets will be displayed here :p";


//Toggles
bool SendToggle = false;
bool SendToToggle = false;
bool WSASendToggle = true;
bool BlockPacketToggle = false;
bool TranslateToAOB = true;
bool Injected = false;
DWORD pid = 0;

void get_proc_id(const char* window_title, DWORD& process_id)
{
    GetWindowThreadProcessId(FindWindow(NULL, window_title), &process_id);
}



bool InitializeSymbolHandler() {
    // Initialize the symbol handler for the current process
    if (!SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
        std::cerr << "Failed to initialize symbol handler! Error code: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

void CleanupSymbolHandler() {
    // Cleanup the symbol handler
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
    // Ouvrir le handle du thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
    if (hThread == NULL) {
        std::cerr << "Failed to open thread! Error code: " << GetLastError() << std::endl;
        return false;
    }

    // Suspendre le thread pour obtenir son contexte
    SuspendThread(hThread);

    // Obtenir le contexte du thread
    CONTEXT context;
    context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &context)) {
        std::cerr << "Failed to get thread context! Error code: " << GetLastError() << std::endl;
        CloseHandle(hThread);
        return false;
    }

    // L'adresse de début du thread est contenue dans le registre Eip (x86) ou Rip (x64)
#ifdef _WIN64
    * lpStartAddress = reinterpret_cast<LPVOID>(context.Rip);
#else
    * lpStartAddress = reinterpret_cast<LPVOID>(context.Eip);
#endif

    // Reprendre le thread
    ResumeThread(hThread);

    // Fermer le handle du thread
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
    }

    ResumeThread(hThread);
    CloseHandle(hThread);
}

void InitImGui()
{
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.ConfigFlags = ImGuiConfigFlags_NoMouseCursorChange;
	ImGui_ImplWin32_Init(window);
	ImGui_ImplDX11_Init(pDevice, pContext);
}

void OutputPacketText(const char text[])
{
    // Check if there's enough space in the Output buffer to append the text
    if (strlen(Output) + strlen(text) < sizeof(Output)) {
        strncat(Output, text, sizeof(Output) - strlen(Output) - 1);
    }
}

// Hooked NtCreateThreadEx function
NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    std::cout << "Thread creation intercepted. Applying sandboxing rules..." << std::endl;
    // Implement your sandboxing logic here
    return OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

//For send() hook it to read the buffer and print it  
int WSAAPI MySend(SOCKET s, const char* buf, int len, int flags)
{
    int result;
    // Check if it's checked
    if (SendToggle == true && len >= FilterPacketSize) {
        OutputPacketText("=======================================\n");
        OutputPacketText("Send() Sent Data : \n");

        // Print buffer content as an array of bytes
        if (TranslateToAOB) {
            OutputPacketText("Buffer content (hex): ");
            for (int i = 0; i < len; ++i)
            {
                // Convert each byte to its hexadecimal representation
                char hex[4];
                sprintf_s(hex, "%02X ", static_cast<unsigned char>(buf[i]));
                OutputPacketText(hex);
            }
        }
        else
        {
            OutputPacketText("Buffer : \n");
            OutputPacketText(buf);
        }
        OutputPacketText("\n");
    }
    if (BlockPacketToggle == false) {
        result = pSend(s, buf, len, flags);
        return result;
    }
    
}


static char InjectedBuffer[50000] = "";

//For WSASEnd() hook it to read the buffer and print it                    
int WSAAPI MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, LPDWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    int result;
    if (WSASendToggle == true) {

        if (lpBuffers[0].len>= FilterPacketSize) //Display packet filtered
        {
            if (Injected && lpBuffers[0].len >= strlen(InjectedBuffer)) { //if packet size is greater than our packet and is not empty then we inject
                OutputPacketText("Found a packet to inject in !\n");
                lpBuffers[0].len = strlen(InjectedBuffer);
                lpBuffers[0].buf = InjectedBuffer;
                OutputPacketText("\n");
                Injected = false;
            }

            //Log packet as usual
            OutputPacketText("=======================================\n");
            OutputPacketText("WSASend() Sent Data : \n");
            for (DWORD i = 0; i < dwBufferCount; ++i)
            {
                const char* bufferContent = reinterpret_cast<const char*>(lpBuffers[i].buf);
                DWORD bufferLength = lpBuffers[i].len;
                if (TranslateToAOB) {
                    // Print buffer content as an array of bytes
                    OutputPacketText("Buffer content (hex): ");
                    for (DWORD j = 0; j < bufferLength; ++j){
                        char hex[4];
                        if (bufferContent[j] == 'G' && bufferContent[j + 1] == 'G') {
                            sprintf_s(hex, "%02X ", 0);  // Replace "GG" with null byte
                            j++; // Skip the next character ('G')
                        }
                        else {
                            sprintf_s(hex, "%02X ", static_cast<unsigned char>(bufferContent[j]));
                        }
                        OutputPacketText(hex);
                    }
                }
                else{
                    OutputPacketText("Buffer : \n");
                    OutputPacketText(bufferContent);
                }
            }

            OutputPacketText("\n");
        } 
    }
    if (BlockPacketToggle == false) {
        //Send packet by injecting our packet into an existing packet
        result = pWsaSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
        return result;
    }

}

// For sendto() hook it to read the buffer and print it
int WSAAPI MySendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    // Call the original sendto() function
    int result;

    // Check if it's checked
    if (SendToToggle == true && len >= FilterPacketSize) {
        OutputPacketText("=======================================\n");
        // Extracting the IP and port of the receiver
        const sockaddr_in* clientService = reinterpret_cast<const sockaddr_in*>(to);
        unsigned long ipAddress = clientService->sin_addr.s_addr;

        std::string MyIpAddress = std::to_string(ipAddress);
        const char* IpConstChar = MyIpAddress.c_str();

        TO_SERVER_IP = static_cast<int>(ipAddress);
        TO_PORT = static_cast<int>(ntohs(clientService->sin_port));

        if (true)
        {
            OutputPacketText("SendTo() Sent Data (hex): \n");

            // Print buffer content as an array of bytes
            if (TranslateToAOB) {
                OutputPacketText("Buffer content (hex): \n");
                for (int i = 0; i < len; ++i)
                {
                    // Convert each byte to its hexadecimal representation
                    char hex[4];
                    sprintf_s(hex, "%02X ", static_cast<unsigned char>(buf[i]));
                    OutputPacketText(hex);
                }
            }
            else
            {
                OutputPacketText("Buffer : \n");
                OutputPacketText(buf);
            }
            OutputPacketText("\n");
        }

        OutputPacketText("\n");
    }
    if (BlockPacketToggle == false) {
        result = pSendTo(s, buf, len, flags, to, tolen);
        return result;
    }
}


//Hook the connect to get the IP and the PORT of the server for (send , recv)
int WSAAPI MyConnect(SOCKET s, const SOCKADDR* sAddr, int nameLen)
{
    // Assuming sAddr is of type SOCKADDR_IN
    const sockaddr_in* clientService = reinterpret_cast<const sockaddr_in*>(sAddr);
    unsigned long ipAddress = clientService->sin_addr.s_addr;

    std::string MyIpAddress = std::to_string(ipAddress);
    const char* IpConstChar = MyIpAddress.c_str();

    SERVER_IP = static_cast<int>(ipAddress);
    PORT = static_cast<int>(ntohs(clientService->sin_port));

    struct in_addr ipAddr;
    ipAddr.s_addr = htonl(ipAddress);

    // Convert to string and print
    std::string ipAddresss = inet_ntoa(ipAddr);


    OutputPacketText("\n");
    OutputPacketText("IP address being used is: ");
    OutputPacketText(ipAddresss.c_str());
    OutputPacketText("\n");

    OutputPacketText("Port being used is: ");
    OutputPacketText(std::to_string(ntohs(clientService->sin_port)).c_str());
    OutputPacketText("\n");

    return pConnect(s, sAddr, nameLen);
}

int WSAAPI MyGetAddrinfo(PCSTR Host, PCSTR port, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
    OutputPacketText("Host : ");
    OutputPacketText((const char*)Host);
    OutputPacketText("\n");
    OutputPacketText("Port : ");
    OutputPacketText((const char*)port);
    OutputPacketText("\n");

    WSA_TO_SERVER_IP = (const char*)Host;
    WSA_TO_PORT = static_cast<int>(PORT);
    return pGetAddrInfo(Host, port, pHints, ppResult);
}


LRESULT __stdcall WndProc(const HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {

	if (true && ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam))
		return true;

	return CallWindowProc(oWndProc, hWnd, uMsg, wParam, lParam);
}

bool init = false;
HRESULT __stdcall hkPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{
	if (!init)
	{
		if (SUCCEEDED(pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)& pDevice)))
		{
			pDevice->GetImmediateContext(&pContext);
			DXGI_SWAP_CHAIN_DESC sd;
			pSwapChain->GetDesc(&sd);
			window = sd.OutputWindow;
			ID3D11Texture2D* pBackBuffer;
			pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)& pBackBuffer);
			pDevice->CreateRenderTargetView(pBackBuffer, NULL, &mainRenderTargetView);
			pBackBuffer->Release();
			oWndProc = (WNDPROC)SetWindowLongPtr(window, GWLP_WNDPROC, (LONG_PTR)WndProc);
			InitImGui();
			init = true;
		}

		else
			return oPresent(pSwapChain, SyncInterval, Flags);
	}
	
	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	ImGui::SetNextWindowSize(ImVec2(500, 350));

	if (ImGui::Begin("Packet logger by RainBot , Discord : accesslist , FREE PALESTINE", NULL, ImGuiWindowFlags_NoResize)) {
		//Output packet
		if (ImGui::TreeNode("Output packets")) {

			static ImGuiInputTextFlags flags = ImGuiInputTextFlags_AllowTabInput;
			ImGui::InputTextMultiline("##source", Output, IM_ARRAYSIZE(Output), ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16), flags);
			ImGui::TreePop();
			//clear output button
			if (ImGui::Button("Clear output")) {
				memset(Output, 0, sizeof(Output));
			}
            ImGui::SliderInt("Filter", &FilterPacketSize, 1, 700);
		}

		//Input packet
		if (ImGui::TreeNode("Input packets")) {
			static ImGuiInputTextFlags flags = ImGuiInputTextFlags_AllowTabInput;
			ImGui::InputTextMultiline("##source", Input, IM_ARRAYSIZE(Input), ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16), flags);
			ImGui::TreePop();

			// Send packet button
			if (ImGui::Button("Send packet")) {
                if (WSASendToggle) {
                    char TempPacket[50000];
                    strcpy(TempPacket,Input);//We take our input and we put in out TempPacket

                    if (TranslateToAOB) {
                        std::string inputText(TempPacket);
                        inputText.erase(std::remove_if(inputText.begin(), inputText.end(), ::isspace), inputText.end());
                        std::string asciiText;
                        for (size_t i = 0; i < inputText.length(); i += 2) {
                            std::string hexValue = inputText.substr(i, 2);
                            if (hexValue == "00") {
                                asciiText += "GG";  // Replace null byte with "GG"
                            }
                            else {
                                char asciiChar = static_cast<char>(std::stoi(hexValue, nullptr, 16));
                                asciiText += asciiChar;
                            }
                        }
                        const char* finaltest = asciiText.c_str();
                        strcpy(InjectedBuffer, finaltest);
                        OutputPacketText("Injected packet successfully !\n");
                    }
                    Injected = true;
                }

                if (SendToggle) {
                    char TempPacket[5000];
                    strcpy(TempPacket, Input);//We take our input and we put in out TempPacket
                    if (TranslateToAOB) {
                        std::string inputText(TempPacket);
                        inputText.erase(std::remove_if(inputText.begin(), inputText.end(), ::isspace), inputText.end());
                        std::string asciiText;
                        for (size_t i = 0; i < inputText.length(); i += 2) {
                            std::string hexValue = inputText.substr(i, 2);
                            if (hexValue == "00") {
                                asciiText += "GG";  // Replace null byte with "GG"
                            }
                            else {
                                char asciiChar = static_cast<char>(std::stoi(hexValue, nullptr, 16));
                                asciiText += asciiChar;
                            }
                        }
                        const char* finaltest = asciiText.c_str();
                        strcpy(InjectedBuffer, finaltest);
                        OutputPacketText("Injected packet successfully !\n");
                    }

                    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    clientService.sin_family = AF_INET;
                    clientService.sin_addr.s_addr = SERVER_IP;
                    clientService.sin_port = htons(PORT);
                    pConnect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));

                    //send()
                    size_t arraySize = strlen(TempPacket);
                    int SentBytes = pSend(ConnectSocket, (const char*)TempPacket, static_cast<int>(arraySize), 0);

                    if (SentBytes != SOCKET_ERROR) {
                        OutputPacketText("Sent packet successfully !\n");
                    }
                    shutdown(ConnectSocket, SD_SEND);
                    closesocket(ConnectSocket);
                }

                if (SendToToggle) {
                    char TempPacket[5000];
                    strcpy(TempPacket, Input);//We take our input and we put in out TempPacket
                    if (TranslateToAOB) {
                        std::string inputText(TempPacket);
                        inputText.erase(std::remove_if(inputText.begin(), inputText.end(), ::isspace), inputText.end());
                        std::string asciiText;
                        for (size_t i = 0; i < inputText.length(); i += 2) {
                            std::string hexValue = inputText.substr(i, 2);
                            if (hexValue == "00") {
                                asciiText += "GG";  // Replace null byte with "GG"
                            }
                            else {
                                char asciiChar = static_cast<char>(std::stoi(hexValue, nullptr, 16));
                                asciiText += asciiChar;
                            }
                        }
                        const char* finaltest = asciiText.c_str();
                        strcpy(InjectedBuffer, finaltest);
                        OutputPacketText("Injected packet successfully !\n");
                    }

                    ConnectSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    clientService.sin_family = AF_INET;
                    clientService.sin_addr.s_addr = SERVER_IP;
                    clientService.sin_port = htons(PORT);

                    size_t arraySize = strlen(TempPacket);
                    int SentBytes = pSendTo(ConnectSocket, (const char*)TempPacket, static_cast<int>(arraySize), 0, (SOCKADDR*)&clientService, sizeof(clientService));

                    if (SentBytes != SOCKET_ERROR) {
                        OutputPacketText("Sent packet successfully using sendto!\n");
                    }
                    closesocket(ConnectSocket);
                }

			}

            if (ImGui::Button("Sandbox packet")) {

            }


			ImGui::Checkbox("Send", &SendToggle);
			ImGui::Checkbox("SendTo", &SendToToggle);
			ImGui::Checkbox("WSASend", &WSASendToggle);
			ImGui::Checkbox("Block Packets", &BlockPacketToggle);
			ImGui::Checkbox("AOB Translate", &TranslateToAOB);
		}
	}



	ImGui::End();
	ImGui::Render();
	pContext->OMSetRenderTargets(1, &mainRenderTargetView, NULL);
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
	return oPresent(pSwapChain, SyncInterval, Flags);
}

DWORD WINAPI MainThread(LPVOID lpReserved)
{
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);

	bool init_hook = false;
	do
	{
		if (kiero::init(kiero::RenderType::D3D11) == kiero::Status::Success)
		{
			kiero::bind(8, (void**)& oPresent, hkPresent);
			init_hook = true;
		}
	} while (!init_hook);


    InitializeSymbolHandler();
    if (!LoadModuleSymbols("C:\\Windows\\System32\\ntdll.dll")) {
        CleanupSymbolHandler();
        return 1;
    }

    pid = GetCurrentProcessId();
    std::cout << "Process ID : " << pid << std::endl;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    Thread32First(hSnapshot, &te32);
    while (Thread32Next(hSnapshot, &te32))
    {
        // Check if the thread belongs to the target process
        if (te32.th32OwnerProcessID == pid)
        {
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
	return TRUE;
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
        myhmod = hMod;
        

		DisableThreadLibraryCalls(hMod);
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)pSend, (PVOID)MySend);
        DetourAttach(&(PVOID&)pConnect, (PVOID)MyConnect);
        DetourAttach(&(PVOID&)pWsaSend, (PVOID)MyWSASend);
        DetourAttach(&(PVOID&)pSendTo, (PVOID)MySendTo);
        DetourAttach(&(PVOID&)pGetAddrInfo, (PVOID)MyGetAddrinfo);

        DetourTransactionCommit();


		CreateThread(nullptr, 0, MainThread, hMod, 0, nullptr);
		break;
	case DLL_PROCESS_DETACH:
		kiero::shutdown();
		break;
	}
	return TRUE;
}
