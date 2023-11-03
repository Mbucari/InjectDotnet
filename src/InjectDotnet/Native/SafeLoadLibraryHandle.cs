using Microsoft.Win32.SafeHandles;
using System;

namespace InjectDotnet.Native;

// SafeHandle to call FreeLibrary
public sealed class SafeLoadLibraryHandle : SafeHandleZeroOrMinusOneIsInvalid
{
	private SafeLoadLibraryHandle() : base(true) { }
	public SafeLoadLibraryHandle(IntPtr handle)
		: base(true)
	{
		SetHandle(handle);
	}

	protected override bool ReleaseHandle()
	{
		return NativeMethods.FreeLibrary(handle);
	}

	// This is technically equivalent to DangerousGetHandle, but it's safer for loaded
	// libraries where the HMODULE is also the base address the module is loaded at.
	public IntPtr BaseAddress
	{
		get
		{
			return handle;
		}
	}
}
