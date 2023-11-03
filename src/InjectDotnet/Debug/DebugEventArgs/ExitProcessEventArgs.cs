using InjectDotnet.Native;

namespace InjectDotnet.Debug;

/// <summary>
/// Provides process termination information for the <see cref="Debugger.ExitProcess"/> event.
/// </summary>
public class ExitProcessEventArgs : DebuggerEventArgs
{
	/// <summary>
	/// The exit code for the process.
	/// </summary>
	public uint ExitCode { get; }
	internal ExitProcessEventArgs(DebugEvent debugEvent)
		: base(debugEvent)
	{
		ExitCode = debugEvent.u.ExitProcess.dwExitCode;
	}
}