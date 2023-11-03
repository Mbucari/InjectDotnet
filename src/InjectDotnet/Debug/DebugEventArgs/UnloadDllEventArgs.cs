using InjectDotnet.Native;

namespace InjectDotnet.Debug;

/// <summary>
/// Provides information about a dynamic-link library (DLL) that has just been unloaded for the <see cref="Debugger.UnloadDll"/> event.
/// </summary>
public class UnloadDllEventArgs : ContinuableDebuggerEventArgs
{
	/// <summary>
	/// A pointer to the base address of the DLL in the address space of the process unloading the DLL.
	/// </summary>
	public nint BaseOfDll { get; }
	internal UnloadDllEventArgs(DebugEvent debugEvent)
		: base(debugEvent)
	{
		BaseOfDll = debugEvent.u.UnloadDll.lpBaseOfDll;
	}
}
