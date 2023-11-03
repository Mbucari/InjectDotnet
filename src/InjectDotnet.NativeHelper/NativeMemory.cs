using InjectDotnet.NativeHelper.Native;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace InjectDotnet.NativeHelper
{
	public static class NativeMemory
	{
		/// <summary>
		/// Iterate over all memory pages in the current process.<br/>
		/// Consecutive pages with identical <see cref="MemoryBasicInformation.AllocationBase"/>,
		/// <see cref="MemoryBasicInformation.State"/>, and
		/// <see cref="MemoryBasicInformation.Protect"/> are grouped together in a single <see cref="MemoryBasicInformation"/>.
		/// </summary>
		/// <param name="startAddress">The virtual address at which the enumeration begins</param>
		/// <returns>An enumerable collection of memory in this process' virtual address space.</returns>
		public static IEnumerable<MemoryBasicInformation> EnumerateMemory(nint startAddress = 0)
		{
			NativeMethods.GetSystemInfo(out var si);

			if (startAddress < si.MinimumApplicationAddress)
				startAddress = si.MinimumApplicationAddress;

			startAddress &= startAddress / (nint)si.PageSize * (nint)si.PageSize;

			var mbiSz = Unsafe.SizeOf<MemoryBasicInformation>();
			do
			{
				if (NativeMethods.VirtualQuery(startAddress, out var mbi, mbiSz) != mbiSz)
					yield break;

				startAddress += mbi.RegionSize;
				yield return mbi;
			} while (startAddress < si.MaximumApplicationAddress);
		}

		/// <summary>
		/// Find the first free region of memory after <paramref name="baseAddress"/>
		/// </summary>
		/// <param name="baseAddress">The virtual memory address to begin searching for free memory</param>
		/// <param name="minFreeSize">The minimum desired size of the free memory block. Actual free size of the block after returned.</param>
		/// <returns>Base address of the free memory block</returns>
		public static nint FirstFreeAddress(nint baseAddress, ref nint minFreeSize)
		{
			var minSize = minFreeSize;
			foreach (var mbi in EnumerateMemory(baseAddress))
			{
				if (mbi.State is not MemoryState.MemFree) continue;
				minFreeSize = mbi.RegionSize - (mbi.BaseAddressRoundedUp - mbi.BaseAddress);

				if (minFreeSize > minSize) return mbi.BaseAddressRoundedUp;
			}
			minFreeSize = 0;
			return 0;
		}

		/// <summary>
		/// Allocate some memory to store a pointer to the hook function. The pointer must be in
		/// range of the exported function so that it can be reached with a long jmp. The Maximum
		/// distance of a long jump offset size is 32 bits in both x86 and x64.
		/// </summary>
		/// <param name="baseAddress">Address in virtual to begin searching for a free memory block</param>
		/// <returns>A pointer to the beginning of the free memory block</returns>
		unsafe public static nint AllocateMemoryNearBase(nint baseAddress)
		{
			nint minSize = sizeof(nint);
			nint allocation = 0;
			do
			{
				var pHookFn = FirstFreeAddress(baseAddress, ref minSize);
				if (pHookFn == 0 || minSize == 0 || pHookFn - baseAddress > uint.MaxValue)
					continue;

				allocation = NativeMethods.VirtualAlloc(
					pHookFn,
					(nint)MemoryBasicInformation.SystemInfo.PageSize,
					AllocationType.ReserveCommit,
					MemoryProtection.ExecuteReadWrite);

				baseAddress = pHookFn;

			} while (allocation == 0);

			return allocation;
		}
	}
}
