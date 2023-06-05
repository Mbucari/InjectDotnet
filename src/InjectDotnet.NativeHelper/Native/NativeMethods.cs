using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper.Native;

public static class NativeMethods
{
	private const string KERNEL32 = "Kernel32.dll";

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern nint GetProcAddress(nint hModule, ushort ordinal);

	[DllImport(KERNEL32, SetLastError = true)]
	public static unsafe extern bool VirtualProtect(nint handle, nint size, MemoryProtection newProtect, MemoryProtection* oldProtect);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern nint VirtualAlloc(nint lpAddress, nint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern int VirtualQuery(nint lpAddress, out MemoryBasicInformation lpBuffer, int dwLength);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern void GetSystemInfo(out SystemInfo lpSystemInfo);
}
