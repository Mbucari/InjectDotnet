using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper.Native;

internal static class NativeMethods
{
	private const string KERNEL32 = "Kernel32.dll";

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern IntPtr GetProcAddress(nint hModule, ushort ordinal);

	[DllImport(KERNEL32, SetLastError = true)]
	public static unsafe extern bool VirtualProtect(nint handle, nint size, MemoryProtection newProtect, MemoryProtection* oldProtect);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern nint VirtualAlloc(nint lpAddress, nint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

	[DllImport(KERNEL32, SetLastError = true)]
	public static unsafe extern int VirtualQuery(nint lpAddress, MemoryBasicInformation* lpBuffer, int dwLength);

	[DllImport(KERNEL32, SetLastError = true)]
	public static unsafe extern void GetSystemInfo(SystemInfo* lpSystemInfo);
}
