using InjectDotnet.Native;

namespace InjectDotnet.Debug;

public abstract class ContinuableDebuggerEventArgs : DebuggerEventArgs
{
	/// <summary>
	/// Gets or sets a value indicating whether the <see cref="Debugger"/> will continue listening for debug events.
	/// </summary>
	public bool Continue { get; set; }

	internal ContinuableDebuggerEventArgs(DebugEvent debugEvent)
		: base(debugEvent)
	{
		Continue = true;
	}
}
