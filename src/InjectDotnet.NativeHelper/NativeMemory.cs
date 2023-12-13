using InjectDotnet.NativeHelper.Native;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

#if !NET
using nint = System.IntPtr;
#endif

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
		/// <returns>An enumerable collection of memory in this process' virtual address space.</returns>
		public static IEnumerable<MemoryBasicInformation> EnumerateMemory()
			=> EnumerateMemory(IntPtr.Zero);


		/// <summary>
		/// Iterate over all memory pages in the current process.<br/>
		/// Consecutive pages with identical <see cref="MemoryBasicInformation.AllocationBase"/>,
		/// <see cref="MemoryBasicInformation.State"/>, and
		/// <see cref="MemoryBasicInformation.Protect"/> are grouped together in a single <see cref="MemoryBasicInformation"/>.
		/// </summary>
		/// <param name="startAddress">The virtual address at which the enumeration begins</param>
		/// <returns>An enumerable collection of memory in this process' virtual address space.</returns>
		public static IEnumerable<MemoryBasicInformation> EnumerateMemory(nint startAddress)
		{
			NativeMethods.GetSystemInfo(out var si);

			if (startAddress.Lt(si.MinimumApplicationAddress))
				startAddress = si.MinimumApplicationAddress;

			startAddress = startAddress.And(startAddress.Div((nint)si.PageSize).Mul((nint)si.PageSize));

			var mbiSz = Marshal.SizeOf<MemoryBasicInformation>();
			do
			{
				if (NativeMethods.VirtualQuery(startAddress, out var mbi, mbiSz) != mbiSz)
					yield break;

				startAddress = startAddress.Add(mbi.RegionSize);
				yield return mbi;
			} while (startAddress.Lt(si.MaximumApplicationAddress));
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
				if (mbi.State != MemoryState.MemFree) continue;
				minFreeSize = mbi.RegionSize.Subtract(mbi.BaseAddressRoundedUp.Subtract(mbi.BaseAddress));

				if (minFreeSize.Gt(minSize)) return mbi.BaseAddressRoundedUp;
			}
			minFreeSize = IntPtr.Zero;
			return IntPtr.Zero;
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
			nint minSize = (nint)sizeof(nint);
			nint allocation = IntPtr.Zero;
			do
			{
				var pHookFn = FirstFreeAddress(baseAddress, ref minSize);
				if (pHookFn == IntPtr.Zero || minSize == IntPtr.Zero)
					continue;

				if (pHookFn.Subtract(baseAddress).Gt((nint)int.MaxValue))
					throw new Exception($"Could not allocate memory within range of 0x{baseAddress.ToString("x" + IntPtr.Size)}");

				allocation = NativeMethods.VirtualAlloc(
					pHookFn,
					(nint)MemoryBasicInformation.SystemInfo.PageSize,
					AllocationType.ReserveCommit,
					MemoryProtection.ExecuteReadWrite);

				baseAddress = pHookFn;

			} while (allocation == IntPtr.Zero);

			return allocation;
		}
	}
}
