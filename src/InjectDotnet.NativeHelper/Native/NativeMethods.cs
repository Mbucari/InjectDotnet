using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper.Native;

public static class NativeMethods
{
	public const string KERNEL32 = "Kernel32.dll";
	public const string ADVAPI32 = "advapi32.dll";

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern nint GetProcAddress(nint hModule, ushort ordinal);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern bool CloseHandle(IntPtr handle);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern void GetSystemInfo(out SystemInfo lpSystemInfo);

	[DllImport(KERNEL32, SetLastError = true)]
	public static unsafe extern bool VirtualProtect(nint handle, nint size, MemoryProtection newProtect, MemoryProtection* oldProtect);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern nint VirtualAlloc(nint lpAddress, nint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

	[DllImport(KERNEL32, CharSet = CharSet.Unicode, ExactSpelling = true)]
	public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, FreeType dwFreeType);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern int VirtualQuery(nint lpAddress, out MemoryBasicInformation lpBuffer, int dwLength);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern void GetSystemInfo(out SystemInfo lpSystemInfo);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitCode);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern bool CloseHandle(IntPtr handle);

	/// <summary>
	/// Opens an existing thread object.
	/// </summary>
	/// <param name="dwDesiredAccess">The access to the thread object. This access right is checked against the security descriptor for the thread. </param>
	/// <param name="bInheritHandle">If this value is <c>true</c>, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.</param>
	/// <param name="dwThreadId">The identifier of the thread to be opened.</param>
	/// <returns>If the function succeeds, the return value is an open handle to the specified thread.
	/// If the function fails, the return value is NULL. To get extended error information, call <see cref="Marshal.GetLastWin32Error"/>.</returns>
	[DllImport(KERNEL32, SetLastError = true)]
	public static extern nint OpenThread(ThreadRights dwDesiredAccess, bool bInheritHandle, int dwThreadId);

	/// <summary>
	/// Suspends the specified thread.
	/// </summary>
	/// <param name="hThread">A handle to the thread to be suspended. This handle must have the <see cref="ThreadRights.THREAD_SUSPEND_RESUME"/> access right.</param>
	/// <returns>f the function succeeds, the return value is the thread's previous suspend count;
	/// otherwise, it is (DWORD) -1. To get extended error information, use the <see cref="Marshal.GetLastWin32Error"/> function.</returns>
	[DllImport(KERNEL32, SetLastError = true)]
	public static extern int SuspendThread(IntPtr hThread);

	/// <summary>
	/// Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is resumed.
	/// </summary>
	/// <param name="hThread">A handle to the thread to be restarted. This handle must have the <see cref="ThreadRights.THREAD_SUSPEND_RESUME"/> access right.</param>
	/// <returns>If the function succeeds, the return value is the thread's previous suspend count.
	/// If the function fails, the return value is -1. To get extended error information, call <see cref="Marshal.GetLastWin32Error"/>.
	/// </returns>
	[DllImport(KERNEL32, SetLastError = true)]
	public static extern int ResumeThread(IntPtr hThread);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern bool GetExitCodeThread(IntPtr hThread, out int lpExitCode);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern int GetCurrentThreadId();

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern int WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern unsafe bool SetThreadContext(IntPtr hThread, Context* lpContext);


	[DllImport(KERNEL32, SetLastError = true)]
	public static extern unsafe bool GetThreadContext(IntPtr hThread, Context* lpContext);


	[DllImport(KERNEL32, SetLastError = true)]
	public unsafe static extern nint AddVectoredExceptionHandler(uint first, delegate* unmanaged[Stdcall]<ExceptionPointers*, int> Handler);

	[DllImport(KERNEL32, SetLastError = true)]
	public static extern bool RemoveVectoredExceptionHandler(IntPtr handle);


	[DllImport(ADVAPI32, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool OpenProcessToken(SafeProcessHandle ProcessHandle, TokenAccessRights DesiredAccess, out SafeAccessTokenHandle TokenHandle);


	[DllImport(ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

	[DllImport(ADVAPI32, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, [In, MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(TokenPrivilegesCustomMarshaler))] TOKEN_PRIVILEGES NewState, int pstateSize, [In, Out, MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(TokenPrivilegesCustomMarshaler))] TOKEN_PRIVILEGES PreviousState, out int ReturnLength);


	[DllImport(ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool LookupPrivilegeName(string? lpSystemName, ref LUID lpLuid, System.Text.StringBuilder lpName, [In, Out] ref int cchName);

}
