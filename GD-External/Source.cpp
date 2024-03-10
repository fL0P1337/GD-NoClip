#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <conio.h>
HWND hwnd;
DWORD procID;
HANDLE hProcess;
uintptr_t GetModuleBaseAddress(const char* modName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (!strcmp(modEntry.szModule, modName)) {
                    CloseHandle(hSnap);
                    return (uintptr_t)modEntry.modBaseAddr;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
}
int main() {

    SetConsoleTitle("NoClip Cheat by flo0p1337");

    hwnd = FindWindow(0, "Geometry Dash");
    if (hwnd == NULL) {
        std::cout << "[-] Please Open the Geometry Dash";
        Sleep(1000);
        return 0;
    }

    procID = 0;
    GetWindowThreadProcessId(hwnd, &procID);

    if (procID == 0) {
        std::cout << "\n[-] Process ID not Found";
        return 0;
    }

    uintptr_t ModuleBase = GetModuleBaseAddress("GeometryDash.exe");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    std::cout << "[+] Process Geometry Dash is Opened";
    std::cout << "\n[+] Process id: " << procID;
    std::cout << "\n[+] lpBaseAddress: 0x" << ModuleBase;
    std::cout << "\n[+] Trying to patch the memory...";
    uintptr_t nc_address = ModuleBase + 0x20A23C;
    std::vector<uint8_t> bytes = {0xE9, 0x79, 0x06, 0x00, 0x00};
    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(nc_address), bytes.data(), bytes.size(), nullptr);
    std::cout << "\n[+] Patched the memory succesfully";
    _getch();
    return 0;
}