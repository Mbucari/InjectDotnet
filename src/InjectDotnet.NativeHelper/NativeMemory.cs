using InjectDotnet.NativeHelper.Native;

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

			do
			{
				if (NativeMethods.VirtualQuery(startAddress, out var mbi, MemoryBasicInformation.NativeSize) != MemoryBasicInformation.NativeSize)
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
			foreach (var mbi in EnumerateMemory(baseAddress).Where(m => m.State is MemoryState.MemFree))
			{
				minFreeSize = mbi.RegionSize - (mbi.BaseAddressRoundedUp - mbi.BaseAddress);

				if (minFreeSize > minSize) return mbi.BaseAddressRoundedUp;
			}
			minFreeSize = 0;
			return 0;
		}
	}
}
