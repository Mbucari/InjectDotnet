using InjectDotnet.NativeHelper.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace InjectDotnet.NativeHelper
{
	public static class NativeMemory
	{
		public static IEnumerable<MemoryBasicInformation> GetMemoryInfo(nint startAddress = 0)
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
	}
}
