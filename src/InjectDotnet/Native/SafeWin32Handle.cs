using Microsoft.Win32.SafeHandles;
using System;

namespace InjectDotnet.Native;

public sealed class SafeWin32Handle : SafeHandleZeroOrMinusOneIsInvalid
{
	public SafeWin32Handle() : base(true) { }

	public SafeWin32Handle(IntPtr handle)
		: base(true)
	{
		SetHandle(handle);
	}


	protected override bool ReleaseHandle()
	{
		return NativeMethods.CloseHandle(handle);
	}
}
