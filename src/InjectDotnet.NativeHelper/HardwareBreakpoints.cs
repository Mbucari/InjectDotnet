using InjectDotnet.NativeHelper.Native;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper;

/// <summary>
/// Contains all <see cref="ThreadBreakpoints"/> registered in this process.
/// </summary>
public static class HardwareBreakpoints
{
	private static Dictionary<int, ThreadBreakpoints> s_BpDict = new();

	/// <summary>
	/// Get the hardware breakpoint registers for a thread.
	/// </summary>
	/// <param name="threadID"><see cref="ProcessThread.Id"/> of the thread</param>
	/// <returns>A valid <see cref="ThreadBreakpoints"/> if successful.</returns>
	public static ThreadBreakpoints? GetThreadBreakpoints(int threadID)
	{
		if (!Process.GetCurrentProcess().Threads.Cast<ProcessThread>().Any(t => t.Id == threadID))
			return null;

		if (!s_BpDict.ContainsKey(threadID))
		{
			s_BpDict[threadID] = new ThreadBreakpoints(threadID);
		}

		return s_BpDict[threadID];
	}
}

/// <summary>
/// Represents the hardware <see cref="Breakpoint"/>s for a single thread in this process.
/// </summary>
public class ThreadBreakpoints
{
	/// <summary>
	/// <see cref="ProcessThread.Id"/> of the thread.
	/// </summary>
	public int ThreadId { get; }
	/// <summary>
	/// The four hardware breakpoints for this thread.
	/// </summary>
	public ReadOnlyCollection<Breakpoint> Breakpoints { get; }

	/// <summary>
	/// Indicates if one of the <see cref="Breakpoints"/> has been changed
	/// but has not been set to the thread's context.
	/// </summary>
	public bool BreakpointNeedsSetting { get; internal set; }

	internal ThreadBreakpoints(int threadId)
	{
		ThreadId = threadId;
		Breakpoints = new(new[]
		{
			new Breakpoint(this, 0),
			new Breakpoint(this, 1),
			new Breakpoint(this, 2),
			new Breakpoint(this, 3),
		});
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
		//Create a new thread to set the breakpoint in case the caller
		//is trying to set one on its own thread.

		var hThread = CreateThread(0, 0, UpdateBreakpointsInternal, this, 0, out var threadId);

		NativeMethods.WaitForSingleObject(hThread, -1);
		NativeMethods.GetExitCodeThread(hThread, out var lpExitCode);

		return BreakpointNeedsSetting = lpExitCode == 0;
	}

	private unsafe static int UpdateBreakpointsInternal(ThreadBreakpoints threadId)
	{
		var handle = NativeMethods.OpenThread(ThreadRights.THREAD_ALL_ACCESS, false, threadId.ThreadId);
		if (handle == 0) return Marshal.GetLastWin32Error();

		nint hMem = 0;
		NativeMethods.SuspendThread(handle);

		try
		{
			//Context must be on a 16-byte boundary. The only way to
			//guarantee that is to allocate a new unmanaged page
			hMem = NativeMethods.VirtualAlloc(
				0,
				sizeof(Context),
				AllocationType.ReserveCommit,
				MemoryProtection.ReadWrite);

			if (hMem == 0) return Marshal.GetLastWin32Error();

			var pCtx = (Context*)hMem;
			pCtx->ContextFlags = ContextFlags.CONTEXT_ALL;

			if (!NativeMethods.GetThreadContext(handle, pCtx)) return Marshal.GetLastWin32Error();

			threadId.SetDebugRegisters(ref pCtx->Dr);

			if (!NativeMethods.SetThreadContext(handle, pCtx)) return Marshal.GetLastWin32Error();

			threadId.BreakpointNeedsSetting = false;
			return 0;
		}
		finally
		{
			if (hMem != 0)
				NativeMethods.VirtualFree(hMem, 0, FreeType.Release);
			NativeMethods.ResumeThread(handle);
			NativeMethods.CloseHandle(handle);
		}
	}

	private void SetDebugRegisters(ref DebugRegisters dr)
	{
		for (int i = 0; i < Breakpoints.Count; i++)
		{
			dr.SetAddress(i, Breakpoints[i].Address);
			dr.SetEnabled(i, Breakpoints[i].Enabled);
			dr.SetCondition(i, Breakpoints[i].Condition);
			dr.SetLength(i, Breakpoints[i].Length);
		}
	}
}

/// <summary>
/// Represents one of the possible four hardware breakpoints for a thread in this process.
/// </summary>
public class Breakpoint
{
	private nint _address;
	private int _register;
	private BreakCondition _condition;
	private BreakLength _length;
	private BreakEnabled _enabled;

	/// <summary>
	/// The <see cref="ThreadBreakpoints"/> to which this <see cref="Breakpoint"/> belongs.
	/// </summary>
	public ThreadBreakpoints ThreadBreakpoints { get; }
	/// <summary>
	/// The Debug register of this breakpoint (Dr0, Dr1, Dr2, or Dr3)
	/// </summary>
	public int Register { get => _register; set => SetValue(ref _register, value); }
	/// <summary>
	/// Virtual address of to break on.
	/// </summary>
	public nint Address { get => _address; set => SetValue(ref _address, value); }
	/// <summary>
	/// The condition under which te processor will throw a break exception.
	/// </summary>
	public BreakCondition Condition { get => _condition; set => SetValue(ref _condition, value); }
	/// <summary>
	/// Breakpoint length. <see cref="BreakLength.QWord"/> is undefined on 32-bit mode.
	/// </summary>
	public BreakLength Length { get => _length; set => SetValue(ref _length, value); }
	/// <summary>
	/// Enabled status.
	/// </summary>
	public BreakEnabled Enabled { get => _enabled; set => SetValue(ref _enabled, value); }
	/// <summary>
	/// The instruction pointer where execution will resume after continuing.
	/// </summary>
	public nint ResumeIP { get; set; }

	internal Breakpoint(ThreadBreakpoints threadBP, int register)
	{
		ThreadBreakpoints = threadBP;
		Register = register;
	}

	private T SetValue<T>(ref T field, T newValue)
	{
		if (field?.Equals(newValue) is not true)
		{
			field = newValue;
			ThreadBreakpoints.BreakpointNeedsSetting = true;
		}
		return field;
	}
}

public enum BreakEnabled : byte
{
	Disabled = 0,
	Local = 1,
	Global = 2
}

public enum BreakCondition : byte
{
	Execute,
	Write,
	ReadWrite_IO,
	ReadWrite_Data,
}

public enum BreakLength : byte
{
	Byte,
	Word,
	QWord,
	DWord,
}

[StructLayout(LayoutKind.Sequential)]
public struct DebugRegisters
{
	private nint _dr0;
	private nint _dr1;
	private nint _dr2;
	private nint _dr3;
	private nint _dr6;
	private nint _dr7;

	/// <summary>
	/// Returns the debug register number on which the break occurred, or -1 if none.
	/// </summary>
	public int DetectedBreakCondition
	=> (_dr6 & 0xf) switch
	{
		1 => 0,
		2 => 1,
		4 => 2,
		8 => 3,
		_ => -1
	};

	public nint GetAddress(int register) => register switch
	{
		0 => _dr0,
		1 => _dr1,
		2 => _dr2,
		3 => _dr3,
		_ => throw new InvalidOperationException()
	};

	public void SetAddress(int register, nint Address)
	{
		switch (register)
		{
			case 0:
				_dr0 = Address;
				break;
			case 1:
				_dr1 = Address;
				break;
			case 2:
				_dr2 = Address;
				break;
			case 3:
				_dr3 = Address;
				break;
			default:
				throw new InvalidOperationException();
		}
	}

	public void SetCondition(int register, BreakCondition condition)
	{
		_dr7 &= ~((nint)3 << (16 + 4 * register));
		_dr7 |= (nint)condition << (16 + 4 * register);
	}
	public void SetLength(int register, BreakLength length)
	{
		_dr7 &= ~((nint)3 << (18 + 4 * register));
		_dr7 |= (nint)length << (18 + 4 * register);
	}
	public void SetEnabled(int register, BreakEnabled enabled)
	{
		_dr7 &= ~((nint)3 << (2 * register));
		_dr7 |= (nint)enabled << (2 * register);
	}
	public BreakCondition GetCondition(int register)
	{
		return (BreakCondition)((_dr7 >> (16 + 4 * register)) & 0x3);
	}

	public BreakEnabled GetEnabled(int register)
	{
		return (BreakEnabled)((_dr7 >> (2 * register)) & 0x3);
	}

	public BreakLength GetLength(int register)
	{
		return (BreakLength)((_dr7 >> (18 + 4 * register)) & 0x3);
	}

	public nint Dr0Address
	{
		get => GetAddress(0);
		set => SetAddress(0, value);
	}
	public nint Dr1Address
	{
		get => GetAddress(1);
		set => SetAddress(1, value);
	}
	public nint Dr2Address
	{
		get => GetAddress(2);
		set => SetAddress(2, value);
	}
	public nint Dr3Address
	{
		get => GetAddress(3);
		set => SetAddress(3, value);
	}

	public BreakCondition Dr0Condition
	{
		get => GetCondition(0);
		set => SetCondition(0, value);
	}

	public BreakLength Dr0Length
	{
		get => GetLength(0);
		set => SetLength(0, value);
	}

	public BreakCondition Dr1Condition
	{
		get => GetCondition(1);
		set => SetCondition(1, value);
	}

	public BreakLength Dr1Length
	{
		get => GetLength(1);
		set => SetLength(1, value);
	}

	public BreakCondition Dr2Condition
	{
		get => GetCondition(2);
		set => SetCondition(2, value);
	}

	public BreakLength Dr2Length
	{
		get => GetLength(2);
		set => SetLength(2, value);
	}

	public BreakCondition Dr3Condition
	{
		get => GetCondition(3);
		set => SetCondition(3, value);
	}

	public BreakLength Dr3Length
	{
		get => GetLength(3);
		set => SetLength(3, value);
	}

	public BreakEnabled Dr0Enabled
	{
		get => GetEnabled(0);
		set => SetEnabled(0, value);
	}

	public BreakEnabled Dr1Enabled
	{
		get => GetEnabled(1);
		set => SetEnabled(1, value);
	}

	public BreakEnabled Dr2Enabled
	{
		get => GetEnabled(2);
		set => SetEnabled(2, value);
	}

	public BreakEnabled Dr3Enabled
	{
		get => GetEnabled(3);
		set => SetEnabled(3, value);
	}

	public override string ToString()
	{
		long temp = 1L << 32 | (uint)_dr7;
		return Convert.ToString(temp, 2).Substring(1);
	}
}