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
	public static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);


	const int PRIVILEGE_SET_ALL_NECESSARY = 1;


	[DllImport(ADVAPI32, SetLastError = true)]
	public unsafe static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle TokenHandle, bool DisableAllPrivileges,void* NewState, int pstateSize, void* PreviousState, out int ReturnLength);

	

	[DllImport(ADVAPI32, SetLastError = true)]
	public unsafe static extern bool PrivilegeCheck(SafeAccessTokenHandle TokenHandle, void* RequiredPrivileges, out bool pfResult);

	public static unsafe bool PrivilegeCheck(SafeAccessTokenHandle TokenHandle, Span<LUID_AND_ATTRIBUTES> luid)
	{
		Span<byte> inBuffer = new byte[luid.Length * sizeof(LUID_AND_ATTRIBUTES) + 2 * sizeof(int)];
		var ints = MemoryMarshal.Cast<byte, int>(inBuffer);
		ints[0] = luid.Length;
		ints[1] = PRIVILEGE_SET_ALL_NECESSARY;

		var tmpLuids = MemoryMarshal.Cast<byte, LUID_AND_ATTRIBUTES>(inBuffer.Slice(2 * sizeof(int)));
		luid.CopyTo(tmpLuids);

		bool success, any;
		fixed (byte* pIn = inBuffer)
			success =  PrivilegeCheck(TokenHandle, pIn, out any);
		tmpLuids.CopyTo(luid);
		return success;
	}

	public static unsafe bool AdjustTokenPrivileges(SafeAccessTokenHandle TokenHandle, bool DisableAllPrivileges, ReadOnlySpan<LUID_AND_ATTRIBUTES> NewState, out LUID_AND_ATTRIBUTES[]? previousState)
	{
		Span<byte> inBuffer = new byte[NewState.Length * sizeof(LUID_AND_ATTRIBUTES) + sizeof(int)];

		MemoryMarshal.Cast<byte, int>(inBuffer)[0] = NewState.Length;
		MemoryMarshal.Cast<LUID_AND_ATTRIBUTES, byte>(NewState).CopyTo(inBuffer.Slice(sizeof(int)));

		Span<byte> outBuffer = new byte[inBuffer.Length];

		bool success = false;int returnLength;
		fixed (byte* pNew = inBuffer)
		{
			fixed (byte* pPrevious = outBuffer)
				success = AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, pNew, outBuffer.Length, pPrevious, out returnLength);
			
			if (!success)
			{
				outBuffer = new byte[returnLength];
				fixed (byte* pPrevious = outBuffer)
					success = AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, pNew, outBuffer.Length, pPrevious, out returnLength);
			}
		}

		if (!success)
		{
			previousState = null;
			return false;
		}

		int numPrevious = MemoryMarshal.Read<int>(outBuffer);

		var attribs = MemoryMarshal.Cast<byte,LUID_AND_ATTRIBUTES>(outBuffer.Slice(sizeof(int), numPrevious * sizeof(LUID_AND_ATTRIBUTES)));
		previousState = attribs.ToArray();
		return true;
	}


	[DllImport(ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
	public static extern bool LookupPrivilegeName(string? lpSystemName, ref LUID lpLuid, System.Text.StringBuilder lpName, [In, Out] ref int cchName);

}
