# SyscallPOC
A simple proof of concept shellcode injector using syscalls.

https://www.solomonsklash.io/syscalls-for-shellcode-injection.html

Currently works for Windows 10 1909 and 2004, with 1909 as the default. You'll need to uncomment the syscall for 2004 in `Syscalls.cs` and comment out the syscall for 1909 to switch to 2004.

This POC was inspired by Jack Halon and his [Utilizing Syscalls in C#](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/) [series](https://jhalon.github.io/utilizing-syscalls-in-csharp-2/) as well as
badBounty's [directinjectorPOC](https://github.com/badBounty/directInjectorPOC). Thanks to both!
