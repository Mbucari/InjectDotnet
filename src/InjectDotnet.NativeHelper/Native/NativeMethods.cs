using System.Runtime.InteropServices;

#if !NET
using nint = System.IntPtr;
#endif

namespace InjectDotnet.NativeHelper.Native
{
	public static class NativeMethods
	{
		public const string KERNEL32 = "Kernel32.dll";
		public const string ADVAPI32 = "advapi32.dll";

		[DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Unicode)]
		public static extern nint LoadLibrary(string lpFileName);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern nint GetProcAddress(nint hModule, ushort ordinal);

		[DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Ansi)]
		public static extern nint GetProcAddress(nint hModule, string ordinal);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern bool CloseHandle(nint handle);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern void GetSystemInfo(out SystemInfo lpSystemInfo);

		[DllImport(KERNEL32, SetLastError = true)]
		public static unsafe extern bool VirtualProtect(nint handle, nint size, MemoryProtection newProtect, MemoryProtection* oldProtect);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern nint VirtualAlloc(nint lpAddress, nint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

		[DllImport(KERNEL32, CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
		public static extern bool VirtualFree(nint lpAddress, int dwSize, FreeType dwFreeType);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern int VirtualQuery(nint lpAddress, out MemoryBasicInformation lpBuffer, int dwLength);

		[DllImport(KERNEL32, CharSet = CharSet.Unicode)]
		public static extern void OutputDebugString(string message);

		/// <summary>
		/// Opens an existing thread object.
		/// </summary>
		/// <param name="dwDesiredAccess">The access to the thread object. This access right is checked against the security descriptor for the thread. </param>
		/// <param name="bInheritHandle">If this value is <c>true</c>, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.</param>
		/// <param name="dwThreadId">The identifier of the thread to be opened.</param>
		/// <returns>If the function succeeds, the return value is an open handle to the specified thread.
		/// If the function fails, the return value == null. To get extended error information, call <see cref="Marshal.GetLastWin32Error"/>.</returns>
		[DllImport(KERNEL32, SetLastError = true)]
		public static extern nint OpenThread(ThreadRights dwDesiredAccess, bool bInheritHandle, int dwThreadId);

		/// <summary>
		/// Suspends the specified thread.
		/// </summary>
		/// <param name="hThread">A handle to the thread to be suspended. This handle must have the <see cref="ThreadRights.THREAD_SUSPEND_RESUME"/> access right.</param>
		/// <returns>f the function succeeds, the return value is the thread's previous suspend count;
		/// otherwise, it is (DWORD) -1. To get extended error information, use the <see cref="Marshal.GetLastWin32Error"/> function.</returns>
		[DllImport(KERNEL32, SetLastError = true)]
		public static extern int SuspendThread(nint hThread);

		/// <summary>
		/// Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is resumed.
		/// </summary>
		/// <param name="hThread">A handle to the thread to be restarted. This handle must have the <see cref="ThreadRights.THREAD_SUSPEND_RESUME"/> access right.</param>
		/// <returns>If the function succeeds, the return value is the thread's previous suspend count.
		/// If the function fails, the return value is -1. To get extended error information, call <see cref="Marshal.GetLastWin32Error"/>.
		/// </returns>
		[DllImport(KERNEL32, SetLastError = true)]
		public static extern int ResumeThread(nint hThread);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern bool GetExitCodeThread(nint hThread, out int lpExitCode);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern int GetCurrentThreadId();

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern int WaitForSingleObject(nint hHandle, int dwMilliseconds);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern unsafe bool SetThreadContext(nint hThread, Context* lpContext);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern unsafe bool GetThreadContext(nint hThread, Context* lpContext);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate int ExceptionHandlerDelegate(ref ExceptionPointers exceptionInfo);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern nint AddVectoredExceptionHandler([MarshalAs(UnmanagedType.Bool)] bool first, ExceptionHandlerDelegate Handler);

		[DllImport(KERNEL32, SetLastError = true)]
		public static extern bool RemoveVectoredExceptionHandler(nint handle);
	}
}