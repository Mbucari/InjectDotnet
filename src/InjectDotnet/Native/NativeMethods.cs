using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace InjectDotnet.Native;

internal class NativeMethods
{
	public const string Kernel32LibraryName = "kernel32.dll";
	private const string PsapiLibraryName = "psapi.dll";

	[DllImport(PsapiLibraryName, CharSet = CharSet.Unicode)]
	private static extern unsafe int GetModuleFileNameEx(nint hProcess, nint hModule, char* lpFilename, int nSize);
	[DllImport(PsapiLibraryName, CharSet = CharSet.Unicode)]
	private static extern unsafe int GetModuleBaseName(nint hProcess, nint hModule, char* lpFilename, int nSize);
	[DllImport(PsapiLibraryName)]
	private static extern unsafe bool GetModuleInformation(nint hProcess, nint hModule, ModuleInfo* lpmodinfo, int cb);

	[DllImport(PsapiLibraryName, SetLastError = true)]
	public static extern unsafe bool EnumProcessModules(IntPtr hProcess, nint* lphModule, int cb, out int lpcbNeeded);


	[DllImport(Kernel32LibraryName, SetLastError = true)]
	internal static extern bool IsWow64Process(SafeProcessHandle process, out bool wow64Process);

	[DllImport(Kernel32LibraryName, SetLastError = true)]
	public static extern IntPtr VirtualAllocEx(nint hProcess,
		nint lpAddress, nint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

	[DllImport(Kernel32LibraryName, SetLastError = true)]
	public static extern IntPtr CreateRemoteThread(SafeProcessHandle hProcess,
		IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
		IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

	[DllImport(Kernel32LibraryName, SetLastError = true)]
	public static extern bool VirtualFreeEx(SafeProcessHandle hProcess,
		IntPtr lpAddress, int dwSize, AllocationType dwFreeType);

	[DllImport(Kernel32LibraryName, SetLastError = true)]
	public static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitCode);

	[DllImport(Kernel32LibraryName)]
	internal static extern void RtlMoveMemory(IntPtr destination, IntPtr source, IntPtr numberBytes);

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool CloseHandle(IntPtr handle);

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	public static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal unsafe static extern bool GetThreadContext(IntPtr hThread, Context lpContext);

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal unsafe static extern bool GetThreadContext(IntPtr hThread, nint lpContext);

	[DllImport(Kernel32LibraryName)]
	public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess,
		[MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
		int dwThreadId);

	[DllImport(Kernel32LibraryName)]
	public static extern SafeWin32Handle OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport(Kernel32LibraryName)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static extern bool SetThreadContext(IntPtr hThread, Context lpContext);
	[DllImport(Kernel32LibraryName)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static extern bool SetThreadContext(IntPtr hThread, nint lpContext);

	// This gets the raw OS thread ID. This is not fiber aware. 
	[DllImport(Kernel32LibraryName)]
	public static extern int GetCurrentThreadId();

	[DllImport(Kernel32LibraryName)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool IsWow64Process(SafeWin32Handle hProcess, ref bool isWow);

	[Flags]
	public enum PageProtection : uint
	{
		NoAccess = 0x01,
		Readonly = 0x02,
		ReadWrite = 0x04,
		WriteCopy = 0x08,
		Execute = 0x10,
		ExecuteRead = 0x20,
		ExecuteReadWrite = 0x40,
		ExecuteWriteCopy = 0x80,
		Guard = 0x100,
		NoCache = 0x200,
		WriteCombine = 0x400,
	}

	// Call CloseHandle to clean up.
	[DllImport(Kernel32LibraryName, SetLastError = true)]
	public static extern SafeWin32Handle CreateFileMapping(SafeFileHandle hFile,
	   IntPtr lpFileMappingAttributes, PageProtection flProtect, uint dwMaximumSizeHigh,
	   uint dwMaximumSizeLow, string lpName);

	[DllImport(Kernel32LibraryName, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool UnmapViewOfFile(IntPtr baseAddress);

	// SafeHandle to call UnmapViewOfFile


	// Call BOOL UnmapViewOfFile(void*) to clean up. 
	[DllImport(Kernel32LibraryName, SetLastError = true)]
	public static extern SafeMapViewHandle MapViewOfFile(SafeWin32Handle hFileMappingObject, uint
	   dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow,
	   IntPtr dwNumberOfBytesToMap);



	[DllImport(Kernel32LibraryName)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static extern bool FreeLibrary(IntPtr hModule);

	[DllImport(Kernel32LibraryName)]
	internal static extern IntPtr LoadLibraryEx(string fileName, int hFile, LoadLibraryFlags dwFlags);

	// Filesize can be used as a approximation of module size in memory.
	// In memory size will be larger because of alignment issues.
	[DllImport(Kernel32LibraryName)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);

	// Get the module's size.
	// This can not be called during the actual dll-load debug event. 
	// (The debug event is sent before the information is initialized)


	// Read memory from live, local process.
	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern unsafe bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
	  byte* lpBuffer, int nSize, out int lpNumberOfBytesRead);

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern unsafe bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
	  byte* lpBuffer, int nSize, out int lpNumberOfBytesRead);

	[DllImport(Kernel32LibraryName, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern unsafe bool VirtualProtectEx(nint hProcess, nint lpAddress,
		nint size, MemoryProtection newProtect, out MemoryProtection oldProtect);

	[DllImport(Kernel32LibraryName, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern unsafe bool VirtualQueryEx(nint hProcess, nint lpAddress,
		out MemoryBasicInformation lpBuffer, int dwLength);



	// Requires WinXp/Win2k03
	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool DebugBreakProcess(IntPtr hProcess);

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool SetEvent(SafeWin32Handle eventHandle);


	#region Attach / Detach APIS
	// constants used in CreateProcess functions
	public enum CreateProcessFlags
	{
		CREATE_NEW_CONSOLE = 0x00000010,

		// This will include child processes.
		DEBUG_PROCESS = 1,

		// This will be just the target process.
		DEBUG_ONLY_THIS_PROCESS = 2,
	}

	[DllImport(Kernel32LibraryName, CharSet = CharSet.Unicode, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool CreateProcess(
		string? lpApplicationName,
		string lpCommandLine,
		ref SECURITY_ATTRIBUTES lpProcessAttributes,
		ref SECURITY_ATTRIBUTES lpThreadAttributes,
		[MarshalAs(UnmanagedType.Bool)]
		bool bInheritHandles,
		CreateProcessFlags dwCreationFlags,
		nint lpEnvironment,
		string? lpCurrentDirectory,
		STARTUPINFO lpStartupInfo,// class
		ProcessInformation lpProcessInformation // class
	);

	// Attach to a process
	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool DebugActiveProcess(int dwProcessId);

	// Detach from a process
	// Requires WinXp/Win2k03
	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool DebugActiveProcessStop(int dwProcessId);

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);


	#endregion // Attach / Detach APIS


	#region Stop-Go APIs

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static extern bool WaitForDebugEventEx(ref DebugEvent pDebugEvent, int dwMilliseconds);

	/// <summary>
	/// Values to pass to ContinueDebugEvent for ContinueStatus
	/// </summary>
	internal enum ContinueStatus : uint
	{
		/// <summary>
		/// This is our own "empty" value
		/// </summary>
		CONTINUED = 0,

		/// <summary>
		/// Debug consumes exceptions. Debugee will never see the exception. Like "gh" in Windbg.
		/// </summary>
		DBG_CONTINUE = 0x00010002,

		/// <summary>
		/// Debug does not interfere with exception processing, this passes the exception onto the debugee.
		/// Like "gn" in Windbg.
		/// </summary>
		DBG_EXCEPTION_NOT_HANDLED = 0x80010001,
	}

	[DllImport(Kernel32LibraryName, SetLastError = true, PreserveSig = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static extern bool ContinueDebugEvent(int dwProcessId, int dwThreadId, ContinueStatus dwContinueStatus);

	#endregion // Stop-Go

	[DllImport(Kernel32LibraryName)]
	public static extern void GetSystemInfo([MarshalAs(UnmanagedType.Struct)] out SYSTEM_INFO lpSystemInfo);

}
