using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace InjectDotnet.Native;

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_INFO
{
	// Don't marshal dwOemId since that's obsolete and lets
	// us avoid marshalling a union.
	internal ProcessorArchitecture wProcessorArchitecture;
	internal ushort wReserved;

	public uint dwPageSize;
	public IntPtr lpMinimumApplicationAddress;
	public IntPtr lpMaximumApplicationAddress;
	public IntPtr dwActiveProcessorMask;
	public uint dwNumberOfProcessors;
	public uint dwProcessorType; // obsolete
	public uint dwAllocationGranularity;
	public ushort dwProcessorLevel;
	public ushort dwProcessorRevision;
}


/// <summary>
/// Contains information about a range of pages in the virtual address space of a process.
/// </summary>
public readonly struct MemoryBasicInformation
{
	/// <summary>
	/// A pointer to the base address of the region of pages.
	/// </summary>
	public readonly nint BaseAddress;
	/// <summary>
	/// A pointer to the base address of a range of pages allocated by the VirtualAlloc function.
	/// The page pointed to by the <see cref="BaseAddress"/> member is contained within this allocation range.
	/// </summary>
	public readonly nint AllocationBase;
	/// <summary>
	/// The memory protection option when the region was initially allocated. This member can be one of the
	/// memory protection constants or 0 if the caller does not have access.
	/// </summary>
	public readonly MemoryProtection AllocationProtect;
	/// <summary>
	/// The size of the region beginning at the base address in which all pages have identical attributes, in bytes.
	/// </summary>
	public readonly nint RegionSize;
	/// <summary>
	/// The state of the pages in the region.
	/// </summary>
	public readonly MemoryState State;
	/// <summary>
	/// The access protection of the pages in the region.
	/// </summary>
	public readonly MemoryProtection Protect;
	/// <summary>
	/// The access protection of the pages in the region. This member is one of the values listed for
	/// the <see cref="AllocationProtect"/> member.
	/// </summary>
	public readonly MemoryType Type;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
	internal uint nLength;
	internal unsafe void* lpSecurityDescriptor;
	internal int bInheritHandle;
}

// Passed to CreateProcess
[StructLayout(LayoutKind.Sequential)]
public class STARTUPINFO
{
	public STARTUPINFO()
	{
		// Initialize size field.
		this.cb = Marshal.SizeOf(this);

		// initialize safe handles 
		this.hStdInput = new SafeFileHandle(new IntPtr(0), false);
		this.hStdOutput = new SafeFileHandle(new IntPtr(0), false);
		this.hStdError = new SafeFileHandle(new IntPtr(0), false);
	}
	public int cb;
	public string? lpReserved;
	public string? lpDesktop;
	public string? lpTitle;
	public int dwX;
	public int dwY;
	public int dwXSize;
	public int dwYSize;
	public int dwXCountChars;
	public int dwYCountChars;
	public int dwFillAttribute;
	public int dwFlags;
	public short wShowWindow;
	public short cbReserved2;
	public nint lpReserved2;
	public SafeFileHandle hStdInput;
	public SafeFileHandle hStdOutput;
	public SafeFileHandle hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public class ProcessInformation
{
	public nint ProcessHandle;
	public nint ThreadHandle;
	public int ProcessId;
	public int ThreadId;
}


[StructLayout(LayoutKind.Sequential)]
public struct ModuleInfo
{
	public nint BaseOfDll;
	public uint SizeOfImage;
	public nint EntryPoint;
}
