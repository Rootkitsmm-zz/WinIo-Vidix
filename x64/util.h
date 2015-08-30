#include<Windows.h>
#include<stdio.h>

#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#pragma comment (lib,"Psapi.lib")

LPVOID GetKernelProcAddress(PCHAR KernelModule, PCHAR FunctionName);