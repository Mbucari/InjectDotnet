using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace InjectDotnet;

internal class NativeMethods
{
	public const string KERNEL32 = "kernel32.dll";

	[DllImport(KERNEL32, SetLastError = true, CallingConvention = CallingConvention.Winapi)]
	internal static extern bool IsWow64Process(SafeProcessHandle process, out bool wow64Process);

	[DllImport(KERNEL32, CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
	public static extern IntPtr VirtualAllocEx(SafeProcessHandle hProcess, nint lpAddress, nint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

	[DllImport(KERNEL32, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern IntPtr CreateRemoteThread(SafeProcessHandle hProcess,
		IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
		IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

	[DllImport(KERNEL32, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

	[DllImport(KERNEL32, CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
	public static extern bool VirtualFreeEx(SafeProcessHandle hProcess, IntPtr lpAddress, int dwSize, AllocationType dwFreeType);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitCode);

	[DllImport(KERNEL32, CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool CloseHandle(IntPtr hObject);

	[DllImport(KERNEL32, SetLastError = true)]
	public static unsafe extern bool WriteProcessMemory(SafeProcessHandle hProcess, IntPtr lpBaseAddress, byte* buffer, int nSize, ref int lpNumberOfBytesWritten);

}
