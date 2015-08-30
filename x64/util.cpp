#include"util.h"

 static LPVOID
GetDriverImageBase(PCHAR BaseName)
{
  LPVOID* BaseAddresses;
  LPVOID  lpDriverAddr = NULL;
  DWORD   cbNeeded;
  ULONG   i;

  // How many drivers are there ?
  EnumDeviceDrivers(NULL, 0, &cbNeeded);

  // Alloc memory
  BaseAddresses = (LPVOID*)malloc(sizeof(LPVOID)*cbNeeded / sizeof(LPVOID));

  // Get drivers!
  if(!EnumDeviceDrivers(BaseAddresses,cbNeeded,&cbNeeded))
    return NULL;  

  // Check names
  for(i = 0; i < cbNeeded / sizeof(LPVOID); i++)
  {
    CHAR FileName[MAX_PATH];
    GetDeviceDriverBaseNameA(BaseAddresses[i], FileName, sizeof(FileName));

    // Is this it?
    if(!_stricmp(FileName, BaseName))
    {
      // Yep!
      lpDriverAddr = BaseAddresses[i];
      break;
    }
  }

  // Free and return
  free(BaseAddresses);
  return lpDriverAddr;
}

// ------------------------------------------------------------------
// GetKernelProcAddress()
// ------------------------------------------------------------------
 LPVOID 
GetKernelProcAddress(PCHAR KernelModule, PCHAR FunctionName)
{
  // Load the module
  HMODULE hModule = LoadLibraryExA(KernelModule, NULL, DONT_RESOLVE_DLL_REFERENCES);
  if(hModule == NULL)
    return NULL;

  // Get address
  LPVOID pFunction = (LPVOID)GetProcAddress(hModule, FunctionName);
  if(pFunction == NULL)
    return NULL;

  // Get base address in ring0
  MODULEINFO ModuleInfo;
  if(!GetModuleInformation(GetCurrentProcess(), hModule, &ModuleInfo, sizeof(ModuleInfo)))
    return NULL;

  // Caclc ring0 VA and return
 // printf("addrees of %p GetDriverImageBase is\r\n ",GetDriverImageBase(KernelModule));
  //  printf("addrees of %p hModule is \r\n",hModule);
	//  printf("addrees of %p pFunction is\r\n ",pFunction);

  return (LPVOID)((CHAR*)pFunction - (CHAR*)hModule + (CHAR*)GetDriverImageBase(KernelModule));
}