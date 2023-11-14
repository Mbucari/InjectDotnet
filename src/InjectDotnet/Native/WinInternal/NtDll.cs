using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace InjectDotnet.Native.WinInternal;

internal static class NtDll
{
	public const string NtDllLibraryName = "ntdll.dll";

	internal enum ProcessInformationClass : uint
	{
		ProcessBasicInformation,
		ProcessDebugPort = 7,
		ProcessWow64Information = 26,
		ProcessImageFileName = 27,
		ProcessBreakOnTermination = 29,
		ProcessProtectionInformation = 61
	}

	public static unsafe PROCESS_BASIC_INFORMATION GetProcessBasicInformation(nint hProcess)
	{
		PROCESS_BASIC_INFORMATION pbi = default;
		var ppbi = &pbi;
		NtQueryInformationProcess(hProcess, ProcessInformationClass.ProcessBasicInformation, (nint)ppbi, sizeof(PROCESS_BASIC_INFORMATION), out _);
		return pbi;
	}


	[DllImport(NtDllLibraryName)]
	internal static extern uint NtQueryInformationProcess(nint hProcess, ProcessInformationClass infoClass,
		nint processInformation, int processInformationLength, out int returnLength);


	[StructLayout(LayoutKind.Sequential)]
	internal struct LIST_ENTRY
	{
		public nint FLink;
		public nint Blink;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct LDR_DATA_TABLE_ENTRY
	{
		public LIST_ENTRY InLoadOrder;
		public LIST_ENTRY InMemoryOrderLinks;
		public LIST_ENTRY InInitOrder;
		public nint DllBase;
		public nint EntryPoint;
		public uint SizeOfImage;
		public UNICODE_STRING FullDllName;
		public UNICODE_STRING BaseDllName;
		public uint Flags;
		public ushort ObsoleteLoadCount;
		public ushort TlsIndex;
		public LIST_ENTRY HashLinks;
		public uint TimeDateStamp;
		public nint EntryPointActivationContext;
		public nint Lock;
	}


	[StructLayout(LayoutKind.Sequential)]
	internal struct PROCESS_BASIC_INFORMATION
	{
		public int ExitStatus;
		public nint PebBaseAddress;
		public nint AffinityMask;
		public nint BasePriority;
		public nint UniqueProcessId;
		public nint InheritedFromUniqueProcessId;

		public readonly unsafe PEB GetPeb(IMemoryReader memoryReader)
			=> memoryReader.ReadStruct<PEB>(PebBaseAddress);
	}


	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct PEB
	{
		public byte InheritedAddressSpace;
		public byte ReadImageFileExecOptions;
		public byte BeingDebugged;
		public byte BitField;
		public nint Mutant;
		public nint ImageBaseAddress;
		public nint LoaderData;
		public nint ProcessParameters;
		public nint SubSystemData;
		public nint ProcessHeap;

		public readonly unsafe PEB_LDR_DATA GetLoaderData(IMemoryReader memoryReader)
			=> memoryReader.ReadStruct<PEB_LDR_DATA>(LoaderData);
		public readonly unsafe RTL_USER_PROCESS_PARAMETERS GetProcessParameters(IMemoryReader memoryReader)
			=> memoryReader.ReadStruct<RTL_USER_PROCESS_PARAMETERS>(ProcessParameters);
	}

	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct PEB_LDR_DATA
	{
		public int Length;
		public int Initialized;
		public nint SsHandle;

		public LIST_ENTRY InLoadOrderModuleList;
		public LIST_ENTRY InMemoryOrderModuleList;
		public LIST_ENTRY InInitializationOrderModuleList;

		public nint EntryInProgress;
		public nint ShutdownInProgress;
		public nint ShutdownThreadId;

		public readonly IEnumerable<LDR_DATA_TABLE_ENTRY> EnumerateMemoryOrder(IMemoryReader memoryReader)
		{
			LDR_DATA_TABLE_ENTRY next = GetInMemory(InMemoryOrderModuleList, memoryReader);
			do
			{
				yield return next;
				next = GetInMemory(next.InMemoryOrderLinks, memoryReader);
			} while (next.InMemoryOrderLinks.FLink != InMemoryOrderModuleList.FLink);
		}

		private readonly unsafe LDR_DATA_TABLE_ENTRY GetInMemory(LIST_ENTRY entry, IMemoryReader memoryReader)
		{
			LDR_DATA_TABLE_ENTRY ldte = default;
			var pLdte = &ldte;
			var offset = (nint)pLdte - (nint)(&pLdte->InMemoryOrderLinks);
			var ldrBytes = new Span<byte>(pLdte, sizeof(LDR_DATA_TABLE_ENTRY));
			memoryReader.ReadMemory(entry.FLink + offset, ldrBytes);
			return ldte;
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	internal unsafe struct RTL_USER_PROCESS_PARAMETERS
	{
		public uint MaximumLength;
		public uint Length;
		public uint Flags;
		public uint DebugFlags;
		public nint ConsoleHandle;
		public uint ConsoleFlags;
		public nint StandardInput;
		public nint StandardOutput;
		public nint StandardError;
		public CURDIR CurrentDirectory;
		public UNICODE_STRING DllPath;
		public UNICODE_STRING ImagePathName;
		public UNICODE_STRING CommandLine;
	}

	internal struct CURDIR
	{
#pragma warning disable CS0649 // Field 'NtDll.CURDIR.DosPath' is never assigned to, and will always have its default value
		public UNICODE_STRING DosPath;
		public nint Handle;
#pragma warning restore CS0649
	}

	internal struct UNICODE_STRING
	{
		public ushort Length;
		public ushort MaximumLength;
		public nint Buffer;

		public readonly string? ReadString(IMemoryReader reader)
		{
			if (Buffer == 0) return null;
			var chars = new byte[Length];
			reader.ReadMemory(Buffer, chars);
			return new string(MemoryMarshal.Cast<byte, char>(chars));
		}
	}
}
