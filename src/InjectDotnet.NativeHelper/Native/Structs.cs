﻿using System;
using System.Diagnostics;
using System.Text;

#if !NET
using nint = System.IntPtr;
#endif

namespace InjectDotnet.NativeHelper.Native
{
	public enum FreeType : uint
	{
		Decommit = 0x4000,
		Release = 0x8000
	}

	[Flags]
	public enum AccessRights : uint
	{
		DELETE = 0x00010000,
		READ_CONTROL = 0x00020000,
		WRITE_DACL = 0x00040000,
		WRITE_OWNER = 0x00080000,
		SYNCHRONIZE = 0x00100000,
		STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DACL | WRITE_OWNER,
		STANDARD_RIGHTS_READ = READ_CONTROL,
		STANDARD_RIGHTS_ALL = 0x001F0000,
		SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
	}

	[Flags]
	public enum AllocationType : uint
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

	[Flags]
	public enum ThreadRights : uint
	{
		THREAD_TERMINATE = 1,
		THREAD_SUSPEND_RESUME = 2,
		THREAD_GET_CONTEXT = 8,
		THREAD_SET_CONTEXT = 0x10,
		THREAD_SET_INFORMATION = 0x20,
		THREAD_QUERY_INFORMATION = 0x40,
		THREAD_SET_THREAD_TOKEN = 0x80,
		THREAD_IMPERSONATE = 0x100,
		THREAD_DIRECT_IMPERSONATION = 0x200,
		THREAD_SET_LIMITED_INFORMATION = 0x400,
		THREAD_QUERY_LIMITED_INFORMATION = 0x800,
		THREAD_RESUME = 0x1000,
		THREAD_ALL_ACCESS = AccessRights.STANDARD_RIGHTS_REQUIRED | AccessRights.SYNCHRONIZE | 0xFFFF,
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

	/// <summary>
	/// The processor architecture of the installed operating system.
	/// </summary>
	public enum ProcessorArchitecture : ushort
	{
		Intel_x86 = 0,
		ARM = 5,
		IA64 = 6,
		AMD64 = 9,
		Arm64 = 12,
		UNKNOWN = ushort.MaxValue
	}

#pragma warning disable CS0649 // Field is never assigned to, and will always have its default value

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

		private static nint granularityMask;
		private static SystemInfo? systemInfo;
		private static nint GetGranularityMask()
		{
			if (granularityMask == IntPtr.Zero)
			{
				granularityMask = (nint)GetSystemInfo().AllocationGranularity - 1;
			}
			return granularityMask;
		}
		private static SystemInfo GetSystemInfo()
		{
			if (systemInfo == null)
			{
				NativeMethods.GetSystemInfo(out var si);
				systemInfo = si;
			}
			return systemInfo.Value;
		}

		public static SystemInfo SystemInfo => GetSystemInfo();

		/// <summary>
		/// The <see cref="BaseAddress"/> rounded up to the nearest multiple of the allocation granularity
		/// </summary>
		public nint BaseAddressRoundedUp
		{
			get
			{
#if NET
				return BaseAddress + GetGranularityMask() & ~GetGranularityMask();
#elif X64
				var mask = GetGranularityMask().ToInt64();
				var baseAddr = BaseAddress.ToInt64();
				return (IntPtr)(baseAddr + mask & ~mask);
#elif X86
				var mask = GetGranularityMask().ToInt32();
				var baseAddr = BaseAddress.ToInt32();
				return (IntPtr)(baseAddr + mask & ~mask);
#endif
			}
		}
		/// <summary>
		/// The <see cref="BaseAddress"/> rounded down to the nearest multiple of the allocation granularity
		/// </summary>
		public nint BaseAddressRoundedDown
		{
			get
			{

#if NET
				return BaseAddress & ~GetGranularityMask();
#elif X64
				var mask = GetGranularityMask().ToInt64();
				var baseAddr = BaseAddress.ToInt64();
				return (IntPtr)(baseAddr & ~mask);
#elif X86
				var mask = GetGranularityMask().ToInt32();
				var baseAddr = BaseAddress.ToInt32();
				return (IntPtr)(baseAddr & ~mask);
#endif

			}
		}
	}

	/// <summary>
	/// Contains information about the current computer system.
	/// </summary>
	public readonly struct SystemInfo
	{
		/// <summary>
		/// The processor architecture of the installed operating system.
		/// </summary>
		public readonly ProcessorArchitecture Architecture;
		[DebuggerBrowsable(DebuggerBrowsableState.Never)]
		private readonly ushort wReserved;
		/// <summary>
		/// The page size and the granularity of page protection and commitment. 
		/// </summary>
		public readonly uint PageSize;
		/// <summary>
		/// A pointer to the lowest memory address accessible to applications and dynamic-link libraries (DLLs).
		/// </summary>
		public readonly nint MinimumApplicationAddress;
		/// <summary>
		/// A pointer to the highest memory address accessible to applications and DLLs.
		/// </summary>
		public readonly nint MaximumApplicationAddress;
		[DebuggerBrowsable(DebuggerBrowsableState.Never)]
		private readonly nint dwActiveProcessorMask;
		/// <summary>
		/// The number of logical processors in the current group. 
		/// </summary>
		public readonly int NumberOfProcessors;
		[DebuggerBrowsable(DebuggerBrowsableState.Never)]
		private readonly uint dwProcessorType;
		/// <summary>
		/// The granularity for the starting address at which virtual memory can be allocated.
		/// </summary>
		public readonly uint AllocationGranularity;
		/// <summary>
		/// The architecture-dependent processor level. It should be used only for display purposes.
		/// </summary>
		public readonly ushort ProcessorLevel;
		[DebuggerBrowsable(DebuggerBrowsableState.Never)]
		private readonly ushort wProcessorRevision;
	}

	internal struct ImageExportDirectory
	{
		public uint Characteristics;
		public uint TimeDateStamp;
		public ushort MajorVersion;
		public ushort MinorVersion;
		public uint Name;
		public uint Base;
		public uint NumberOfFunctions;
		public uint NumberOfNames;
		public uint AddressOfFunctions;
		public uint AddressOfNames;
		public uint AddressOfNameOrdinals;
	}
	internal struct ImageImportDescriptor
	{
		public uint OriginalFirstThunk;
		public uint TimeDateStamp;
		public uint ForwarderChain;
		public uint Name;
		public uint FirstThunk;
	}

	internal struct ImageDataDirectory
	{
		public uint RVA;
		public uint Size;
	}

	internal struct ImageSectionHeader
	{
		private readonly ulong _Name;
		public uint VirtualSize;
		public uint VirtualAddress;
		public uint SizeOfRawData;
		public uint PointerToRawData;
		public uint PointerToRelocations;
		public uint PointerToLinenumbers;
		public ushort NumberOfRelocations;
		public ushort NumberOfLinenumbers;
		public uint Characteristics;

		public string Name
		{
			get
			{
				var nameBts = BitConverter.GetBytes(_Name);
				int len = 8;
				for (; len > 0; len--)
				{
					if (nameBts[len - 1] != 0) break;
				}

				return Encoding.UTF8.GetString(nameBts, 0, len);
			}
		}
		public override string ToString() => Name;
	}
}