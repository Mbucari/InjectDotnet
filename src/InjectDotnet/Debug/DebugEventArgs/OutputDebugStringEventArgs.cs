using InjectDotnet.Native;

namespace InjectDotnet.Debug;

/// <summary>
/// Provides data for the <see cref="Debugger.OutputDebugString"/> event.
/// </summary>
public class OutputDebugStringEventArgs : ContinuableDebuggerEventArgs
{
	/// <summary>
	/// The debugging string output by the debugee.
	/// </summary>
	public string? DebugString { get; }
	internal OutputDebugStringEventArgs(IMemoryAccess memoryAccess, DebugEvent debugEvent)
		: base(debugEvent)
	{
		DebugString = debugEvent.u.OutputDebugString.ReadMessageFromTarget(memoryAccess);
	}
}
