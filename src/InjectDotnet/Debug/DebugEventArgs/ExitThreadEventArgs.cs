using InjectDotnet.Native;

namespace InjectDotnet.Debug;

/// <summary>
/// Provides thread termination information for the <see cref="Debugger.ExitThread"/> event.
/// </summary>
public class ExitThreadEventArgs : ContinuableDebuggerEventArgs
{
	/// <summary>
	/// The exit code for the thread.
	/// </summary>
	public uint ExitCode { get; }
	internal ExitThreadEventArgs(DebugEvent debugEvent)
		: base(debugEvent)
	{
		ExitCode = debugEvent.u.ExitThread.dwExitCode;
	}
}