using System;

namespace InjectDotnet.Native;

/// <summary>
/// Describes the ProcessorArchitecture in a SYSTEM_INFO field.
/// This can also be reported by a dump file.
/// </summary>
public enum ProcessorArchitecture : ushort
{
	PROCESSOR_ARCHITECTURE_INTEL = 0,
	PROCESSOR_ARCHITECTURE_MIPS = 1,
	PROCESSOR_ARCHITECTURE_ALPHA = 2,
	PROCESSOR_ARCHITECTURE_PPC = 3,
	PROCESSOR_ARCHITECTURE_SHX = 4,
	PROCESSOR_ARCHITECTURE_ARM = 5,
	PROCESSOR_ARCHITECTURE_IA64 = 6,
	PROCESSOR_ARCHITECTURE_ALPHA64 = 7,
	PROCESSOR_ARCHITECTURE_MSIL = 8,
	PROCESSOR_ARCHITECTURE_AMD64 = 9,
	PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 = 10,
}

/// <summary>
/// memory-protection options
/// </summary>
[Flags]
public enum MemoryProtection : uint
{
	_NoAccess,
	NoAccess = 0x01,
	ReadOnly = 0x02,
	ReadWrite = 0x04,
	WriteCopy = 0x08,
	Execute = 1 << 4,
	ExecuteRead = ReadOnly << 4,
	ExecuteReadWrite = ReadWrite << 4,
	ExecuteWriteCopy = WriteCopy << 4,
	Guard = 0x100,
	NoCache = 0x200,
	WriteCombine = 0x400,
}

/// <summary>
/// The state of memory pages in a region.
/// </summary>
public enum MemoryState : uint
{
	/// <summary>
	///  Indicates committed pages for which physical storage has been allocated, either in memory or in the paging file on disk. 
	/// </summary>
	MemCommit = 0x1000,
	/// <summary>
	///  Indicates reserved pages where a range of the process's virtual address space is reserved without any physical storage
	///  being allocated. For reserved pages, the information in the <see cref="MemoryBasicInformation.Protect"/> member is undefined. 
	/// </summary>
	MemReserve = 0x2000,
	/// <summary>
	///  Indicates free pages not accessible to the calling process and available to be allocated.
	///  For free pages, the information in the <see cref="MemoryBasicInformation.AllocationBase"/>,
	///  <see cref="MemoryBasicInformation.AllocationProtect"/>, <see cref="MemoryBasicInformation.Protect"/>,
	///  and <see cref="MemoryBasicInformation.Type"/> members is undefined. 
	/// </summary>
	MemFree = 0x10000,
}

/// <summary>
/// The type of memory pages in a region
/// </summary>
public enum MemoryType : uint
{
	/// <summary>
	/// Indicates that the memory pages within the region are mapped into the view of an image section. 
	/// </summary>
	MemImage = 0x1000000,
	/// <summary>
	/// Indicates that the memory pages within the region are mapped into the view of a section. 
	/// </summary>
	MemMapped = 0x40000,
	/// <summary>
	/// Indicates that the memory pages within the region are private (that is, not shared by other processes). 
	/// </summary>
	MemPrivate = 0x20000,
}


[Flags]
public enum LoadLibraryFlags : uint
{
	NoFlags = 0x00000000,
	DontResolveDllReferences = 0x00000001,
	LoadIgnoreCodeAuthzLevel = 0x00000010,
	LoadLibraryAsDatafile = 0x00000002,
	LoadLibraryAsDatafileExclusive = 0x00000040,
	LoadLibraryAsImageResource = 0x00000020,
	LoadWithAlteredSearchPath = 0x00000008
}

public enum ThreadAccess : int
{
	None = 0,
	THREAD_ALL_ACCESS = 0x1F03FF,
	THREAD_DIRECT_IMPERSONATION = 0x0200,
	THREAD_GET_CONTEXT = 0x0008,
	THREAD_IMPERSONATE = 0x0100,
	THREAD_QUERY_INFORMATION = 0x0040,
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
	THREAD_SET_CONTEXT = 0x0010,
	THREAD_SET_INFORMATION = 0x0020,
	THREAD_SET_LIMITED_INFORMATION = 0x0400,
	THREAD_SET_THREAD_TOKEN = 0x0080,
	THREAD_SUSPEND_RESUME = 0x0002,
	THREAD_TERMINATE = 0x0001,
}

[Flags]
public enum AllocationType
{
	Commit = 0x1000,
	Reserve = 0x2000,
	Decommit = 0x4000,
	Release = 0x8000,
	Reset = 0x80000,
	Physical = 0x400000,
	TopDown = 0x100000,
	WriteWatch = 0x200000,
	LargePages = 0x20000000,
	ReserveCommit = Reserve | Commit
}
