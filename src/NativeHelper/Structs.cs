using System.Text;

namespace NativeHelper;


[Flags]
internal enum AllocationType
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
internal enum MemoryProtection : uint
{
	NoAccess = 0x01,
	ReadOnly = 0x02,
	ReadWrite = 0x04,
	WriteCopy = 0x08,
	Execute = 0x10,
	ExecuteRead = 0x20,
	ExecuteReadWrite = 0x40,
	ExecuteWriteCopy = 0x80,
	Guard = 0x100,
	NoCache = 0x200,
	WriteCombine = 0x400
}

internal enum MemoryState : uint
{
	MemCommit = 0x1000,
	MemReserve = 0x2000,
	MemFree = 0x10000,
}

#pragma warning disable CS0649 // Field is never assigned to, and will always have its default value


internal struct MemoryBasicInformation
{
	public nint BaseAddress;
	public nint AllocationBase;
	public MemoryProtection AllocationProtect;
	public nint RegionSize;
	public MemoryState State;
	public uint Protect;
	public uint Type;
}

internal unsafe struct SystemInfo
{
	public uint dwOemId;
	public uint dwPageSize;
	public nint lpMinimumApplicationAddress;
	public nint lpMaximumApplicationAddress;
	public uint* dwActiveProcessorMask;
	public uint dwNumberOfProcessors;
	public uint dwProcessorType;
	public uint dwAllocationGranularity;
	public ushort wProcessorLevel;
	public ushort wProcessorRevision;
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