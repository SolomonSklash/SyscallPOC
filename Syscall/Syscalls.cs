using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static Syscall.Native;

namespace Syscall
{
    class Syscalls
    {
        /*
        MSDN:
        NTSTATUS NtAllocateVirtualMemory(
            HANDLE ProcessHandle,         // C#: IntPtr
            PVOID* BaseAddress,           // C#: IntPtr
            ULONG_PTR ZeroBits,           // C#: IntPtr
            PSIZE_T RegionSize,           // C#: ref UIntPtr 
            ULONG AllocationType,         // C#: UInt32
            ULONG Protect                 // C#: UInt32
            );
        ReactOS:
        NTSTATUS NtAllocateVirtualMemory(
            _In_ HANDLE ProcessHandle,
            _Inout_ _Outptr_result_buffer_(* RegionSize) PVOID *BaseAddress,
            _In_ ULONG_PTR ZeroBits,
            _Inout_ PSIZE_T RegionSize,
            _In_ ULONG AllocationType,
            _In_ ULONG Protect
            ); */
        /*   0x18 in all Windows 10 version so far   */
        static byte[] bNtAllocateVirtualMemory =
        {
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
            0xb8, 0x18, 0x00, 0x00, 0x00,   // mov eax,18h
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref UIntPtr RegionSize,
            uint AllocationType,
            uint Protect )
        {
            // set byte array of bNtAllocateVirtualMemory to new byte array called syscall
            byte[] syscall = bNtAllocateVirtualMemory;

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtAllocateVirtualMemory
                    Delegates.NtAllocateVirtualMemory assembledFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)assembledFunction(
                        ProcessHandle,
                        ref BaseAddress,
                        ZeroBits,
                        ref RegionSize,
                        AllocationType,
                        Protect);
                }
            }
        }

        // https://securityxploded.com/ntcreatethreadex.php
        //NTSTATUS NtCreateThreadEx(
            // OUT PHANDLE hThread,                         // C#: out IntPtr
            // IN ACCESS_MASK DesiredAccess,                // C#: ACCESS_MASK (Native.cs)
            // IN LPVOID ObjectAttributes,                  // C#: IntPtr.Zero
            // IN HANDLE ProcessHandle,                     // C#: IntPtr
            // IN LPTHREAD_START_ROUTINE lpStartAddress,    // C#: IntPtr
            // IN LPVOID lpParameter,                       // C#: IntPtr
            // IN BOOL CreateSuspended,                     // C#: Boolean/Int
            // IN ULONG StackZeroBits,                      // C#: uint
            // IN ULONG SizeOfStackCommit,                  // C#: uint
            // IN ULONG SizeOfStackReserve,                 // C#: uint
            // OUT LPVOID lpBytesBuffer                     // C#: IntPtr
            // );
        /*   Windows 10 1909: 0xBD, Windows 10 2004: 0xC1   */
        static byte[] bNtCreateThreadEx =
        {
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
        //    0xb8, 0xc1, 0x00, 0x00, 0x00,   // mov eax,0BDh
            0xb8, 0xbd, 0x00, 0x00, 0x00,   // mov eax,0BDh
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };
        public static NTSTATUS NtCreateThreadEx(
            out IntPtr hThread,
            ACCESS_MASK DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            uint StackZeroBits,
            uint SizeOfStackCommit,
            uint SizeOfStackReserve,
            IntPtr lpBytesBuffer
            )
        {
            // set byte array of bNtCreateThread to new byte array called syscall
            byte[] syscall = bNtCreateThreadEx;

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                    {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtCreateThread
                    Delegates.NtCreateThreadEx assembledFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));

                    return (NTSTATUS)assembledFunction(
                        out hThread,
                        DesiredAccess,
                        ObjectAttributes,
                        ProcessHandle,
                        lpStartAddress,
                        lpParameter,
                        CreateSuspended,
                        StackZeroBits,
                        SizeOfStackCommit,
                        SizeOfStackReserve,
                        lpBytesBuffer
                        );
                }
            }
        }

        /*
        MSDN:
        NTSTATUS ZwWaitForSingleObject(
            HANDLE Handle,             // C#: IntPtr
            BOOLEAN Alertable,         // C#: Boolean
            PLARGE_INTEGER Timeout     // C#: Int64
            );
        ReactOS:
        NTSTATUS NtWaitForSingleObject(
             In_ HANDLE Object,
             In_ BOOLEAN Alertable,
             In_opt_ PLARGE_INTEGER Time
             ); */
        /*   0x4 in all Windows 10 versions so far   */
        static byte[] bNtWaitForSingleObject =
        {
            0x4c, 0x8b, 0xd1,               // mov r10,rcx
            0xb8, 0x04, 0x00, 0x00, 0x00,   // mov eax,4
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };
        public static NTSTATUS NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout)
        {
            // set byte array of bNtWaitForSingleObject to new byte array called syscall
            byte[] syscall = bNtWaitForSingleObject;

            // specify unsafe context
            unsafe
            {
                // create new byte pointer and set value to our syscall byte array
                fixed (byte* ptr = syscall)
                {
                    // cast the byte array pointer into a C# IntPtr called memoryAddress
                    IntPtr memoryAddress = (IntPtr)ptr;

                    // Change memory access to RX for our assembly code
                    if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint oldprotect))
                        {
                        throw new Win32Exception();
                    }

                    // Get delegate for NtWaitForSingleObject
                    Delegates.NtWaitForSingleObject assembledFunction = (Delegates.NtWaitForSingleObject)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWaitForSingleObject));

                    return (NTSTATUS)assembledFunction(Object, Alertable, Timeout);
                }
            }
        }
        public struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtAllocateVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref UIntPtr RegionSize,
                ulong AllocationType,
                ulong Protect);
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtCreateThreadEx(
                out IntPtr hThread,
                ACCESS_MASK DesiredAccess,
                IntPtr ObjectAttributes,
                IntPtr ProcessHandle,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                bool CreateSuspended,
                uint StackZeroBits,
                uint SizeOfStackCommit,
                uint SizeOfStackReserve,
                IntPtr lpBytesBuffer
                );
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout);
        }
    }
}
