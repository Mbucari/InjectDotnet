using InjectDotnet.Native;

namespace InjectDotnet.Debug;

public enum BreakType
{
	Other = 0,
	/// <summary>
	/// The system breakpoint. Raised after the loader has run but before the entry point.
	/// </summary>
	System,
	/// <summary>
	/// Breakpoint at the debugee's entry point.
	/// </summary>
	EntryPoint,
	/// <summary>
	/// A single-step break.
	/// </summary>
	SingleStep,
	/// <summary>
	/// A user-defined memory breakpoint. See <see cref="UserBreakpoint"/>.
	/// </summary>
	UserMemory,
}

/// <summary>
/// Provides exception information for the <see cref="Debugger.Breakpoint"/> event.
/// </summary>
public class BreakpointEventArgs : ContinuableDebuggerEventArgs
{
	/// <summary>
	/// The address where the exception occurred.
	/// </summary>
	public nint Address { get; }
	/// <summary>
	/// The type of breakpoint encountered.
	/// </summary>
	public BreakType Type { get; }
	/// <summary>
	/// If <see cref="Type"/> is <see cref="BreakType.UserMemory"/>, the <see cref="UserBreakpoint"/> that was hit.
	/// </summary>
	public UserBreakpoint? Breakpoint { get; }

	internal BreakpointEventArgs(BreakType type, DebugEvent debugEvent, UserBreakpoint? breakpoint = null)
		: base(debugEvent)
	{
		Type = type;
		Address = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
		Breakpoint = breakpoint;
	}

	public override string ToString()
	{
		return $"{Type} Break: 0x{Address:x}";
	}
}