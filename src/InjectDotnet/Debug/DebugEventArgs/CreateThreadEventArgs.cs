using InjectDotnet.Native;

namespace InjectDotnet.Debug;

/// <summary>
/// Provides thread-creation information for the <see cref="Debugger.CreateThread"/> event.
/// </summary>
public class CreateThreadEventArgs : ContinuableDebuggerEventArgs
{
	/// <summary>
	/// A handle to the thread whose creation caused the debugging event.
	/// </summary>
	/// <remarks>
	///  If this member is <see cref="null"/>, the handle is not valid.
	///  Otherwise, the debugger has THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
	///  and THREAD_SUSPEND_RESUME access to the thread, allowing the debugger
	///  to read from and write to the registers of the thread and control
	///  execution of the thread.
	///  </remarks>
	public nint Handle { get; }
	/// <summary>
	/// A pointer to a block of data. At offset 0x2C into this block is
	/// another pointer, called ThreadLocalStoragePointer, that points to an
	/// array of per-module thread local storage blocks. This gives a
	/// debugger access to per-thread data in the threads of the process being
	/// debugged using the same algorithms that a compiler would use.
	/// </summary>
	public nint ThreadLocalBase { get; }
	/// <summary>
	/// A pointer to the starting address of the thread. This value may only
	/// be an approximation of the thread's starting address, because any
	/// application with appropriate access to the thread can change the
	/// thread's context by using the SetThreadContext function.
	/// </summary>
	public nint StartAddress { get; }
	internal CreateThreadEventArgs(DebugEvent debugEvent)
		: base(debugEvent)
	{
		Handle = debugEvent.u.CreateThread.hThread;
		ThreadLocalBase = debugEvent.u.CreateThread.lpThreadLocalBase;
		StartAddress = debugEvent.u.CreateThread.lpStartAddress;
	}
}
