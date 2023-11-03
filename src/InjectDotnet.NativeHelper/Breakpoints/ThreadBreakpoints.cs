using InjectDotnet.NativeHelper.Native;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper.Breakpoints;

/// <summary>
/// Represents the hardware <see cref="Breakpoint"/>s for a single thread in this process.
/// </summary>
public class ThreadBreakpoints : IEnumerable<Breakpoint>
{
	/// <summary>
	/// <see cref="ProcessThread.Id"/> of the thread.
	/// </summary>
	public int ThreadId { get; }
	/// <summary>
	/// The four hardware breakpoints for this thread.
	/// </summary>

	private readonly Breakpoint[] _hwBreakpoints;
	private static readonly Dictionary<int, ThreadBreakpoints> s_BpDict = new();

	public Breakpoint this[DebugRegister register]
	{
		get => register switch
		{
			DebugRegister.Dr0 => _hwBreakpoints[0],
			DebugRegister.Dr1 => _hwBreakpoints[1],
			DebugRegister.Dr2 => _hwBreakpoints[2],
			DebugRegister.Dr3 => _hwBreakpoints[3],
			_ or DebugRegister.None => throw new ArgumentOutOfRangeException(nameof(register)),
		};
	}
	/// <summary>
	/// Get the hardware breakpoint registers for a thread.
	/// </summary>
	/// <param name="threadID"><see cref="ProcessThread.Id"/> of the thread</param>
	/// <returns>A valid <see cref="ThreadBreakpoints"/> if successful.</returns>
	public static ThreadBreakpoints? GetThreadBreakpoints(int threadId)
	{
		var hThread = NativeMethods.OpenThread(ThreadRights.THREAD_QUERY_LIMITED_INFORMATION, false, threadId);

		if (hThread == 0)
			return null;

		try
		{
			if (!s_BpDict.ContainsKey(threadId))
			{
				s_BpDict[threadId] = new ThreadBreakpoints(threadId);
			}

			return s_BpDict[threadId];
		}
		finally
		{
			NativeMethods.CloseHandle(hThread);
		}
	}


	/// <summary>
	/// Indicates if one of the <see cref="Breakpoints"/> has been changed
	/// but has not been set to the thread's context.
	/// </summary>
	public bool BreakpointNeedsSetting { get; internal set; }

	internal ThreadBreakpoints(int threadId)
	{
		ThreadId = threadId;
		_hwBreakpoints = new[]
		{
			new Breakpoint(this, DebugRegister.Dr0),
			new Breakpoint(this, DebugRegister.Dr1),
			new Breakpoint(this, DebugRegister.Dr2),
			new Breakpoint(this, DebugRegister.Dr3),
		};
	}

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	private delegate int ThreadProcDelegate(ThreadBreakpoints id);

	[DllImport(NativeMethods.KERNEL32, SetLastError = true)]
	private static extern nint CreateThread(
	nint lpThreadAttributes, uint dwStackSize, ThreadProcDelegate lpStartAddress,
	ThreadBreakpoints lpParameter, uint dwCreationFlags, out int lpThreadId);

	/// <summary>
	/// Suspends <see cref="ThreadId"/>, sets the <see cref="DebugRegisters"/>, then resumes the thread.
	/// </summary>
	/// <returns>Success</returns>
	public bool SetDebugRegisters()
	{
		lock (this)
		{
			//Create a new thread to set the breakpoint in case the caller
			//is trying to set one on its own thread.
			var hThread = CreateThread(0, 0, UpdateBreakpointsInternal, this, 0, out var threadId);

			NativeMethods.WaitForSingleObject(hThread, -1);
			NativeMethods.GetExitCodeThread(hThread, out var lpExitCode);

			return BreakpointNeedsSetting = lpExitCode == 0;
		}
	}

	private unsafe static int UpdateBreakpointsInternal(ThreadBreakpoints threadId)
	{
		const ThreadRights threadAccess =
			ThreadRights.THREAD_GET_CONTEXT |
			ThreadRights.THREAD_SET_CONTEXT |
			ThreadRights.THREAD_SUSPEND_RESUME;

		var threadHandle = NativeMethods.OpenThread(threadAccess, false, threadId.ThreadId);
		if (threadHandle == 0)
			throw new Win32Exception($"{nameof(NativeMethods.OpenThread)} failed.");

		if (NativeMethods.SuspendThread(threadHandle) == -1)
			throw new Win32Exception($"{nameof(NativeMethods.SuspendThread)} failed.");

		try
		{
			var pCtx = Context.GetThreadContext(threadHandle);

			threadId.SetDebugRegisters(ref pCtx->Dr);

			if (!NativeMethods.SetThreadContext(threadHandle, pCtx))
				throw new Win32Exception($"{nameof(NativeMethods.SetThreadContext)} failed.");

			threadId.BreakpointNeedsSetting = false;
			return 0;
		}
		finally
		{
			NativeMethods.ResumeThread(threadHandle);
			NativeMethods.CloseHandle(threadHandle);
		}
	}

	private void SetDebugRegisters(ref DebugRegisters dr)
	{
		for (var r = DebugRegister.Dr0; r <= DebugRegister.Dr3; r++)
		{
			dr.SetAddress(r, this[r].Address);
			dr.SetEnabled(r, this[r].Enabled);
			dr.SetCondition(r, this[r].Condition);
			dr.SetLength(r, this[r].Length);
		}
	}

	public IEnumerator<Breakpoint> GetEnumerator()
		=> _hwBreakpoints.Cast<Breakpoint>().GetEnumerator();

	IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}