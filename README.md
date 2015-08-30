# WinIo-Vidix

Vidix: https://en.wikipedia.org/wiki/Vidix
WinIo : http://www.internals.com/

Exploit code for two driver that share  same piece of code for direct I/O port and physical memory access under Windows NT/2000/XP/2003/Vista/7 and 2008. 

Exploit use  Buffer OvferFlow for gain code  execution but diffrent trick for exploit in x64 and x86.

x86
----
in x86 i convert Stack  OvferFlow to  prefect "Write What in Where" condition with "partial stack overflow" and  modify some local variable that was used as destination address for  memcpy  in next code path ,  finaly   abuse   nt!HalDispatchTable for gain code execution with this  prefect W3 condition we can  use Milion way to gain system level like null ACL of other process add ACCESS_MASK to our token ,... 
saved retuen address was protcted with stack_cookie so we cant modidy it

x64
---
in x64 we cant convert  OvferFlow to  prefect "Write What in Where"   our stack address cant modify other local variable in stack becuse  overflow start in higher memory address comper to other local variable( stack grow  to lower memory as you know :) )

but  in this  case  ther wasn't any stack_cookie  so we can abuse return address in stack, next challenge  was how i can return to user in safe  manner or you will see BSOD ? i used KeUserModeCallback for safe return to user mode  

what i done:
1) find real KeUserModeCallback address in kernel for use in  payload
2) trigger vulnerability (send  ioctl )

what payload  do :

1.  call shellcode ( you can use any shellcode to  steal token or disable driver singing enforcement )
2.  hook PEB->KernelCallbackTable with function that create CMD.exe and  exit -- save exit without BSOD)( i hooked  KernelCallbackTable in user mode  but after ioctl system fix  my hook ?!) so i port it to kernel 
3.  call KeUserModeCallback-> jump to hooked function in user mode  (boom :) )




