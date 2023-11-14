using InjectDotnet.Native;
using System;

namespace InjectDotnet.Debug;

public class SingleStepEventArgs : ContinuableDebuggerEventArgs, IException
{
	public nint Address { get; }
	public bool FirstChance { get; }
	public bool Handled { get; set; } = true;
	public SingleStepEventArgs(DebugEvent debugEvent) : base(debugEvent)
	{
		Address = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
		FirstChance = debugEvent.u.Exception.dwFirstChance != 0;
	}

	public override string ToString()
	{
		return "Single Step: 0x" + Address.ToString($"x{IntPtr.Size * 2}");
	}
}
