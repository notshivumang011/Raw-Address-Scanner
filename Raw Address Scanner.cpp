#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>
#include <sddl.h> 
#include <vector>
#include <set>
#include <string>
#include <iomanip>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib") 

void SetConsoleColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void GetThreadIds(DWORD pid, std::vector<DWORD>& threadIds) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create thread snapshot: " << GetLastError() << std::endl;
        return;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threadIds.push_back(te32.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
}

bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

bool PrintRemoteThreadStackTrace(DWORD pid, DWORD tid) {
    bool suspiciousFound = false;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hThread) {
        CloseHandle(hProcess);
        return false;
    }

    if (SuspendThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    STACKFRAME64 stackFrame = { 0 };
    stackFrame.AddrPC.Offset = context.Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context.Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context.Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;

    if (!SymInitialize(hProcess, NULL, TRUE)) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return false;
    }

    DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
    while (StackWalk64(machineType, hProcess, hThread, &stackFrame, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        DWORD64 moduleBase = SymGetModuleBase64(hProcess, stackFrame.AddrPC.Offset);
        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;
        DWORD64 displacement = 0;

        if (!SymFromAddr(hProcess, stackFrame.AddrPC.Offset, &displacement, pSymbol)) {
            if (!moduleBase) {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::cout << "ID: " << std::dec << tid
                    << " | 0x" << std::hex << stackFrame.AddrPC.Offset
                    << " - [!] Suspicious Thread Found" << std::endl;
                std::cout << std::dec;
                suspiciousFound = true;
            }
        }

        IMAGEHLP_LINE64 line = { 0 };
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        DWORD lineDisplacement = 0;
        if (SymGetLineFromAddr64(hProcess, stackFrame.AddrPC.Offset, &lineDisplacement, &line)) {
            SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << " " << line.FileName << " (Line " << std::dec << line.LineNumber << ")\n";
        }

        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    SymCleanup(hProcess);
    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return suspiciousFound;
}

std::wstring GetCurrentUserSid() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return L"";
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return L"";
    }

    std::vector<BYTE> tokenUserBuffer(tokenInfoLength);
    if (!GetTokenInformation(hToken, TokenUser, tokenUserBuffer.data(), tokenInfoLength, &tokenInfoLength)) {
        CloseHandle(hToken);
        return L"";
    }

    TOKEN_USER* tokenUser = (TOKEN_USER*)tokenUserBuffer.data();
    LPWSTR sidString = NULL;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString)) {
        CloseHandle(hToken);
        return L"";
    }

    std::wstring currentUserSid(sidString);
    LocalFree(sidString);
    CloseHandle(hToken);
    return currentUserSid;
}

bool IsProcessOwnedByCurrentUser(DWORD pid, const std::wstring& currentUserSid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return false;
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    std::vector<BYTE> tokenUserBuffer(tokenInfoLength);
    if (!GetTokenInformation(hToken, TokenUser, tokenUserBuffer.data(), tokenInfoLength, &tokenInfoLength)) {
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return false;
    }

    TOKEN_USER* tokenUser = (TOKEN_USER*)tokenUserBuffer.data();
    LPWSTR sidString = NULL;
    if (ConvertSidToStringSidW(tokenUser->User.Sid, &sidString)) {
        std::wstring processUserSid(sidString);
        LocalFree(sidString);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return processUserSid == currentUserSid;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return false;
}

int main() {
    SetConsoleTitleA("Developed By SH!VUMANG");

    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable SeDebugPrivilege. Run as Administrator." << std::endl;
        system("pause");
        return 1;
    }

    std::wstring currentUserSid = GetCurrentUserSid();
    if (currentUserSid.empty()) {
        std::cerr << "Failed to get current user SID." << std::endl;
        system("pause");
        return 1;
    }

    std::set<std::wstring> excludedProcesses = {
        L"GCC.exe", L"RRGsrv.exe", L"GBT_DL_LIB.exe", L"devenv.exe",
        L"PerfWatson2.exe", L"Servicelub.ThreadedMailDialog.exe",
        L"Servicelub.IndexingService.exe", L"Servicelub.IntellicodeModeIService.exe",
        L"Vctip.exe", L"MSBuild.exe", L"AntiCheat Part 2 - Stack Fucker.exe", L"conhost.exe",
        L"OpenConsole.exe", L"ServiceHub.IndexingService.exe"
    };

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot: " << GetLastError() << std::endl;
        system("pause");
        return 1;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        std::cerr << "Failed to get first process: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        system("pause");
        return 1;
    }

    do {
        std::wstring procName = pe32.szExeFile;

        if (excludedProcesses.count(procName)) continue;

        DWORD pid = pe32.th32ProcessID;

        if (!IsProcessOwnedByCurrentUser(pid, currentUserSid)) continue;

        SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"[+] Checking Process: " << procName << L" (PID: " << pid << L")\n";

        std::vector<DWORD> threadIds;
        GetThreadIds(pid, threadIds);

        bool foundSuspicious = false;
        for (DWORD tid : threadIds) {
            if (PrintRemoteThreadStackTrace(pid, tid)) {
                foundSuspicious = true;
            }
        }

        if (!foundSuspicious) {
            SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::wcout << L" No Suspicious Thread\n";
        }
        std::wcout << std::endl;
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    system("pause");
    return 0;
}
