using InjectDotnet.Native;

namespace InjectDotnet.Debug;

/// <summary>
/// Provides information for the <see cref="Debugger.RIP"/> event about the
/// error that caused the RIP (rest in peace) debug event.
/// </summary>
public class RIPEventArgs : DebuggerEventArgs
{
	/// <summary>
	/// The error that caused the RIP debug event.
	/// </summary>
	public uint Error { get; }
	/// <summary>
	/// Any additional information about the type of error that caused the RIP debug event.
	/// </summary>
	public RipErrorType Type { get; }

	internal RIPEventArgs(DebugEvent debugEvent) : base(debugEvent)
	{
		Error = debugEvent.u.Rip.dwError;
		Type = debugEvent.u.Rip.Type;
	}
}