# WinIo-Vidix

Vidix: https://en.wikipedia.org/wiki/Vidix
WinIo : http://www.internals.com/

Exploit code for two drivers that share the same piece of code both for direct I/O port and for physical memory access under Windows NT/2000/XP/2003/Vista/7 and 2008.

The exploit uses buffer ovferFlow to gain code execution but the exploit trick is different on x64 and x86.

x86
----
On x86 I convert Stack  OvferFlow to  prefect "Write What in Where" condition with "partial stack overflow" and  modify some local variable that was used as destination address for  memcpy  in next code path ,  finaly   abuse   nt!HalDispatchTable for gain code execution with this  prefect W3 condition we can  use Milion way to gain system level like null ACL of other process add ACCESS_MASK to our token ,... 
saved retuen address was protcted with stack_cookie so we cant modify it

x64
---
in x64 we cant convert  OvferFlow to  prefect "Write What in Where"   our stack address cant modify other local variable in stack becuse  overflow start in higher memory address comper to other local variable( stack grow  to lower memory as you know :) so we can  just modify return address )

but  in this  case  there wasn't any stack_cookie  so we can abuse return address in stack, next challenge  was how i can return to user in safe  manner or you will see BSOD ? i used KeUserModeCallback for safe return to user mode  

what i done:
1) find real KeUserModeCallback address in kernel for use in  payload
2) trigger vulnerability (send  ioctl )


what payload  do :

1.  call shellcode ( you can use any shellcode to  steal token or disable driver singing enforcement )
2.  hook PEB->KernelCallbackTable with function that create CMD.exe and  exit -- save exit without BSOD)( i hooked  KernelCallbackTable in user mode  but after ioctl system fix  my hook ?!) so i port it to kernel 
3.  call KeUserModeCallback-> jump to hooked function in user mode  (boom :) )




KernelCallbackTable will call  KiCallUserMode and you will see floating-point Instructions

```
nt!KiCallUserMode:
fffff800`016c6840 4881ec38010000  sub     rsp,138h
fffff800`016c6847 488d842400010000 lea     rax,[rsp+100h]
fffff800`016c684f 0f29742430      movaps  xmmword ptr [rsp+30h],xmm6
fffff800`016c6854 0f297c2440      movaps  xmmword ptr [rsp+40h],xmm7
fffff800`016c6859 440f29442450    movaps  xmmword ptr [rsp+50h],xmm8
fffff800`016c685f 440f294c2460    movaps  xmmword ptr [rsp+60h],xmm9
fffff800`016c6865 440f29542470    movaps  xmmword ptr [rsp+70h],xmm10
fffff800`016c686b 440f295880      movaps  xmmword ptr [rax-80h],xmm11
fffff800`016c6870 440f296090      movaps  xmmword ptr [rax-70h],xmm12
fffff800`016c6875 440f2968a0      movaps  xmmword ptr [rax-60h],xmm13
fffff800`016c687a 440f2970b0      movaps  xmmword ptr [rax-50h],xmm14
fffff800`016c687f 440f2978c0      movaps  xmmword ptr [rax-40h],xmm15
fffff800`016c6884 488968f8        mov     qword ptr [rax-8],rbp
```

>
When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte boundary or a general-protection exception (#GP) is generated.
>


so stack address must be  aligned:) i dont  fix this part in my code :))) 

