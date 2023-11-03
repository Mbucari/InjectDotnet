using InjectDotnet.Native;
using System;
using System.Diagnostics;

namespace InjectDotnet.Debug;

public abstract class DebuggerEventArgs : EventArgs, IDisposable
{
	/// <summary>
	/// The code that identifies the type of debugging event.
	/// </summary>
	public DebugEventCode DebugEventCode { get; }
	/// <summary>
	/// The identifier of the process in which the debugging event occurred.
	/// A debugger uses this value to locate the debugger's per-process structure.
	/// These values are not necessarily small integers that can be used as table indices.
	/// </summary>
	public int ProcessId { get; }
	/// <summary>
	/// The identifier of the thread in which the debugging event occurred.
	/// A debugger uses this value to locate the debugger's per-thread structure.
	/// These values are not necessarily small integers that can be used as table indices.
	/// </summary>
	public int ThreadId { get; }
	/// <summary>
	/// The thread context for <see cref="ThreadId"/>
	/// </summary>
	public Context Context { get; }

	private nint ThreadHandle;

	/// <summary>
	/// Get a <see cref="Process"/> for the <see cref="ProcessId"/>
	/// </summary>
	/// <returns></returns>
	public Process GetProcess() => Process.GetProcessById(ProcessId);

	internal DebuggerEventArgs(DebugEvent debugEvent)
	{
		DebugEventCode = debugEvent.DebugEventCode;
		ProcessId = debugEvent.ProcessId;
		ThreadId = debugEvent.ThreadId;
		ThreadHandle = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, false, debugEvent.ThreadId);
		Context = Context.GetThreadContext(ThreadHandle, ContextFlags.ContextAll);
	}

	public void Dispose()
	{
		Dispose(disposing: true);
		GC.SuppressFinalize(this);
	}

	private bool disposed = false;
	protected virtual void Dispose(bool disposing)
	{
		if (!disposed)
		{
			NativeMethods.SetThreadContext(ThreadHandle, Context);
			NativeMethods.CloseHandle(ThreadHandle);
			ThreadHandle = 0;
		}
		disposed = true;
	}
}
