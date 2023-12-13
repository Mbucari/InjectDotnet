using InjectDotnet.Native;
using InjectDotnet.Native.WinInternal;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using static InjectDotnet.Native.NativeMethods;

namespace InjectDotnet.Debug;

/// <summary>
/// A managed win32 debugger.
/// </summary>
public class Debugger
{
	/// <summary>
	/// Occurs when a debugee outputs a debugging string.
	/// </summary>
	public event EventHandler<OutputDebugStringEventArgs>? OutputDebugString;
	/// <summary>
	/// Occurs when a dynamic-link library (DLL) that has just been loaded
	/// </summary>
	public event EventHandler<LoadDllEventArgs>? LoadDll;
	/// <summary>
	/// Occurs when a dynamic-link library (DLL) that has just been unloaded
	/// </summary>
	public event EventHandler<UnloadDllEventArgs>? UnloadDll;
	/// <summary>
	/// Occurs when a thread has been created.
	/// </summary>
	public event EventHandler<CreateThreadEventArgs>? CreateThread;
	/// <summary>
	/// Occurs when a thread has exited.
	/// </summary>
	public event EventHandler<ExitThreadEventArgs>? ExitThread;
	/// <summary>
	/// Occurs when a non-breakpoint exception has occurred.
	/// </summary>
	public event EventHandler<ExceptionEventArgs>? Exception;
	/// <summary>
	/// Occurs when a process has been created.
	/// </summary>
	public event EventHandler<CreateProcessEventArgs>? CreateProcess;
	/// <summary>
	/// Occurs when a process has exited.
	/// </summary>
	public event EventHandler<ExitProcessEventArgs>? ExitProcess;
	/// <summary>
	/// Occurs when a breakpoint exception is encountered.
	/// </summary>
	public event EventHandler<BreakpointEventArgs>? Breakpoint;
	/// <summary>
	/// Occurs when a single step exception is encountered.
	/// </summary>
	public event EventHandler<SingleStepEventArgs>? SingleStep;
	/// <summary>
	/// Occurs when a RIP (rest in peace) error has occurred.
	/// </summary>
	public event EventHandler<RIPEventArgs>? RIP;
	/// <summary>
	/// The debugee executable's file path.
	/// </summary>
	public string ImagePath { get; }
	/// <summary>
	/// The command line used to create the debugee process.
	/// </summary>
	public string CommandLine { get; }
	/// <summary>
	/// Startup information about the debugee process.
	/// </summary>
	public ProcessInformation ProcessInfo { get; } = new();
	/// <summary>
	/// A collection of <see cref="UserBreakpoint"/>s.
	/// </summary>
	public BreakpointCollection Breakpoints { get; } = new();
	/// <summary>
	/// Relative virtual address of the debugee's executable entry point.
	/// </summary>
	public nint EntryPointRVA { get; }
	/// <summary>
	/// The debugee's executable image base.
	/// </summary>
	public nint ImageBase { get; }
	/// <summary>
	/// Address of the debugee's executable entry point.
	/// </summary>
	public nint EntryPoint { get; }
	/// <summary>
	/// Accessor to read, write, and query the debugee's memory.
	/// </summary>
	public IMemoryAccess MemoryAccess { get; }
	/// <summary>
	/// Indicates whether execution has passed the system breakpoint.
	/// </summary>
	public bool HasHitEntryPoint { get; private set; }
	/// <summary>
	/// Indicates whether execution has passed the debugee's entry point.
	/// </summary>
	public bool HitSystemBreakpoint { get; private set; }

	private CancellationToken CancellationToken;
	private readonly Task DebugProcessTask;
	private readonly Dictionary<int, UserBreakpoint> BreaksToResume = new();
	private readonly ManualResetEvent DebugLoopWaitHandle = new(false);

	private const int WAIT_FOR_DEBUG_TIMEOUT = 100;

	/// <summary>
	/// Create a new process to be debugged.<br/>
	/// The debugee will suspend and can be resumed by awaiting <see cref="ResumeProcessAsync(CancellationToken)"/>
	/// </summary>
	/// <param name="exePath">file path to the executable to debug</param>
	/// <param name="arguments">command line arguments to pass to the executable</param>
	/// <exception cref="ArgumentNullException"></exception>
	/// <exception cref="FileNotFoundException"></exception>
	public Debugger(string exePath, string? arguments)
	{
		if (string.IsNullOrEmpty(exePath))
			throw new ArgumentNullException(nameof(exePath));

		if (!File.Exists(exePath))
			throw new FileNotFoundException(nameof(exePath), exePath);

		ImagePath = Path.GetFullPath(exePath);
		CommandLine = $"\"{ImagePath}\" {arguments}";
		EntryPointRVA = GetEntryPointRvaFromFile(ImagePath);

		var addresses = new Tuple<nint, nint>(0, 0);
		using var createProcWaitHandle = new ManualResetEvent(false);
		nint imageBase = 0;
		DebugProcessTask = Task.Run(() => StartInternal(ib => imageBase = ib, createProcWaitHandle));
		//Wait for the process to be created
		createProcWaitHandle.WaitOne();

		//StartInternal sets imageBase before signaling the wait handle
		ImageBase = imageBase;
		EntryPoint = ImageBase + EntryPointRVA;

		MemoryAccess = new MemoryAccessor(ProcessInfo.ProcessHandle);
	}
	/// <summary>
	/// Attach to an existing process to debug.<br/>
	/// The debugee will suspend and can be resumed by awaiting <see cref="ResumeProcessAsync(CancellationToken)"/>
	/// </summary>
	/// <param name="activeProcess">Process Id of the process to debug</param>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="InvalidDataException"></exception>
	public Debugger(Process activeProcess)
	{
		if (activeProcess.HasExited)
			throw new ArgumentException("Process has exited.", nameof(activeProcess));

		if (activeProcess.MainModule?.FileName is not string fileName || !File.Exists(fileName))
			throw new FileNotFoundException("Can't find main module file name", nameof(activeProcess));

		ImageBase = activeProcess.MainModule.BaseAddress;
		EntryPoint = activeProcess.MainModule.EntryPointAddress;
		EntryPointRVA = EntryPoint - ImageBase;

		using var attachProcWaitHandle = new ManualResetEvent(false);
		DebugProcessTask = Task.Run(() => AttachInternal(activeProcess.Id, attachProcWaitHandle));
		attachProcWaitHandle.WaitOne();
		//Wait for the process to be attached to get ProcessInfo
		MemoryAccess = new MemoryAccessor(ProcessInfo.ProcessHandle);

		var procParams
			= NtDll
			.GetProcessBasicInformation(ProcessInfo.ProcessHandle)
			.GetPeb(MemoryAccess)
			.GetProcessParameters(MemoryAccess);

		ImagePath = procParams.ImagePathName.ReadString(MemoryAccess)
			?? throw new InvalidDataException($"Could not read {nameof(procParams.ImagePathName)} from PEB");

		CommandLine = procParams.CommandLine.ReadString(MemoryAccess)
			?? throw new InvalidDataException($"Could not read {nameof(procParams.CommandLine)} from PEB");
	}

	/// <summary>
	/// Resumes process execution
	/// </summary>
	/// <param name="cancellationToken">The <see cref="System.Threading.CancellationToken"/> that the debugger will observe.</param>
	/// <returns>The debugger loop <see cref="Task"/></returns>
	/// <exception cref="InvalidOperationException"></exception>
	public Task ResumeProcessAsync(CancellationToken cancellationToken = default)
	{
		if (DebugProcessTask.IsCompleted)
			throw new InvalidOperationException("The debug loop has already exited.");

		CancellationToken = cancellationToken;
		DebugLoopWaitHandle.Set();
		return DebugProcessTask;
	}

	/// <summary>
	/// Create a memory breakpoint in the debugee
	/// </summary>
	/// <param name="address">Memory address in the debugee to break on.</param>
	/// <param name="name">The breakpoint's name</param>
	public UserBreakpoint GetOrCreateBreakpoint(nint address, string? name = null)
	{
		if (Breakpoints.GetByAddress(address) is UserBreakpoint bp)
			return bp;

		bp = new UserBreakpoint(address, MemoryAccess, name);
		Breakpoints.Add(bp);
		return bp;
	}

	/// <summary>
	/// Create a new process to be debugged.
	/// </summary>
	/// <param name="setImageBase">delegate to set the new process's image base after creation</param>
	/// <param name="createProcWaitHandle">Wait handle to set after the process has been created and <paramref name="setImageBase"/> has been set</param>
	/// <exception cref="Win32Exception"></exception>
	private void StartInternal(Action<nint> setImageBase, ManualResetEvent createProcWaitHandle)
	{
		STARTUPINFO startupInfo = new();
		SECURITY_ATTRIBUTES unused_SecAttrs = default;

		var resultOK = NativeMethods.CreateProcess(
						null,
						CommandLine,
						ref unused_SecAttrs,
						ref unused_SecAttrs,
						true,
						CreateProcessFlags.DEBUG_PROCESS,
						0,
						null,
						startupInfo,
						ProcessInfo);


		DebugEvent debugEvent = default;
		if (!resultOK || ProcessInfo.ProcessHandle == 0 ||
			!WaitForDebugEventEx(ref debugEvent, -1) ||
			debugEvent.DebugEventCode != DebugEventCode.CREATE_PROCESS_DEBUG_EVENT)
			throw new Win32Exception("Failed to create process");

		setImageBase(debugEvent.u.CreateProcess.lpBaseOfImage);

		//Only the thread that created the process being debugged can call
		//WaitForDebugEvent.Notify the constructor that the process has been created
		//then wait to start the debug loop until user calls ResumeProcessAsync.
		createProcWaitHandle.Set();
		DebugLoopWaitHandle.WaitOne();

		//We need to past the CREATE_PROCESS_DEBUG_EVENT on init to capture
		//the image base, but we'd still like to report this event to the
		//user and allow them a chance to cancel debugging.
		var bContinue = OnCreateProcess(debugEvent);
		ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, ContinueStatus.DBG_CONTINUE);
		if (bContinue)
			DebugLoop();

		StopDebugging();
	}

	/// <summary>
	/// Attach to an existing process to debug.
	/// </summary>
	/// <param name="procId">process Id of the process to debug</param>
	/// <param name="attachProcWaitHandle">Wait handle to set after the process has been created</param>
	/// <exception cref="Win32Exception"></exception>
	private void AttachInternal(int procId, ManualResetEvent attachProcWaitHandle)
	{
		DebugEvent debugEvent = default;
		if (!DebugActiveProcess(procId) ||
			!WaitForDebugEventEx(ref debugEvent, -1) ||
			debugEvent.DebugEventCode != DebugEventCode.CREATE_PROCESS_DEBUG_EVENT)
			throw new Win32Exception($"Failed to attached to process {procId}");

		ProcessInfo.ThreadId = debugEvent.ThreadId;
		ProcessInfo.ProcessId = debugEvent.ProcessId;
		ProcessInfo.ProcessHandle = debugEvent.u.CreateProcess.hProcess;
		ProcessInfo.ThreadHandle = debugEvent.u.CreateProcess.hThread;

		attachProcWaitHandle.Set();
		DebugLoopWaitHandle.WaitOne();

		//We need to past the CREATE_PROCESS_DEBUG_EVENT on init to capture
		//the process handle and ID, but we'd still like to report this
		//event to the user and allow them a chance to cancel debugging.
		var bContinue = OnCreateProcess(debugEvent);
		ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, ContinueStatus.DBG_CONTINUE);
		if (bContinue)
			DebugLoop();

		StopDebugging();
	}

	/// <summary>
	/// Get the AddressOfEntryPoint from the PE optional headers
	/// </summary>
	/// <param name="imagePath">Path the the PE file</param>
	/// <returns>Entry point RVA</returns>
	private static int GetEntryPointRvaFromFile(string imagePath)
	{
		var fs = File.Open(imagePath, FileMode.Open, FileAccess.Read, FileShare.Read);
		using var br = new BinaryReader(fs);
		fs.Position = 0x3c;
		var e_lfanew = br.ReadInt32();
		fs.Position = e_lfanew + 0x28;
		return br.ReadInt32();
	}

	/// <summary>
	/// The main debug loop
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	private void DebugLoop()
	{
		bool bContinue = true;

		while (bContinue && !CancellationToken.IsCancellationRequested)
		{
			DebugEvent debugEvent = default;
			if (!WaitForDebugEventEx(ref debugEvent, WAIT_FOR_DEBUG_TIMEOUT))
				continue;

			var passException = false;

			bContinue = debugEvent.DebugEventCode switch
			{
				DebugEventCode.EXCEPTION_DEBUG_EVENT => OnException(debugEvent, out passException),
				DebugEventCode.CREATE_THREAD_DEBUG_EVENT => OnCreateThread(debugEvent),
				DebugEventCode.CREATE_PROCESS_DEBUG_EVENT => OnCreateProcess(debugEvent),
				DebugEventCode.EXIT_THREAD_DEBUG_EVENT => OnExitThread(debugEvent),
				DebugEventCode.EXIT_PROCESS_DEBUG_EVENT => OnExitProcess(debugEvent),
				DebugEventCode.LOAD_DLL_DEBUG_EVENT => OnLoadDll(debugEvent),
				DebugEventCode.UNLOAD_DLL_DEBUG_EVENT => OnUnloadDll(debugEvent),
				DebugEventCode.OUTPUT_DEBUG_STRING_EVENT => OnOutputDebugString(debugEvent),
				DebugEventCode.RIP_EVENT => OnRIP(debugEvent),
				_ or DebugEventCode.None => throw new InvalidOperationException($"Invalid debug event code: {debugEvent.DebugEventCode}"),
			};

			var continueStatus
				= passException ? ContinueStatus.DBG_EXCEPTION_NOT_HANDLED
				: ContinueStatus.DBG_CONTINUE;

			ContinueDebugEvent(debugEvent.ProcessId, debugEvent.ThreadId, continueStatus);
		}
	}

	/// <summary>
	/// Clears all breakpoints and detaches the debugger.
	/// </summary>
	protected virtual void StopDebugging()
	{
		Breakpoints.Clear();
		DebugActiveProcessStop(ProcessInfo.ProcessId);
	}

	protected virtual bool OnOutputDebugString(DebugEvent debugEvent)
	{
		if (OutputDebugString is null)
			return true;
		else
		{
			using var args = new OutputDebugStringEventArgs(MemoryAccess, debugEvent);
			OutputDebugString?.Invoke(this, args);
			return args.Continue;
		}
	}

	protected virtual bool OnLoadDll(DebugEvent debugEvent)
	{
		if (LoadDll is null)
			return true;
		else
		{
			using var args = new LoadDllEventArgs(MemoryAccess, debugEvent);
			LoadDll?.Invoke(this, args);
			return args.Continue;
		}
	}

	protected virtual bool OnUnloadDll(DebugEvent debugEvent)
	{
		if (UnloadDll is null)
			return true;
		else
		{
			using var args = new UnloadDllEventArgs(debugEvent);
			UnloadDll?.Invoke(this, args);
			return args.Continue;
		}
	}

	protected virtual bool OnCreateThread(DebugEvent debugEvent)
	{
		if (CreateThread is null)
			return true;
		else
		{
			using var args = new CreateThreadEventArgs(debugEvent);
			CreateThread?.Invoke(this, args);
			return args.Continue;
		}
	}

	protected virtual bool OnExitThread(DebugEvent debugEvent)
	{
		if (ExitThread is null)
			return true;
		else
		{
			using var args = new ExitThreadEventArgs(debugEvent);
			ExitThread?.Invoke(this, args);
			return args.Continue;
		}
	}

	protected virtual bool OnRIP(DebugEvent debugEvent)
	{
		if (RIP is not null)
		{
			using var args = new RIPEventArgs(debugEvent);
			RIP?.Invoke(this, args);
		}
		return false;
	}

	protected virtual bool OnExitProcess(DebugEvent debugEvent)
	{
		if (ExitProcess is not null)
		{
			using var args = new ExitProcessEventArgs(debugEvent);
			ExitProcess?.Invoke(this, args);
		}
		return false;
	}

	protected virtual bool OnCreateProcess(DebugEvent debugEvent)
	{
		if (CreateProcess is null)
			return true;
		else
		{
			using var args = new CreateProcessEventArgs(MemoryAccess, debugEvent);
			CreateProcess?.Invoke(this, args);
			return args.Continue;
		}
	}

	protected virtual bool OnException(DebugEvent debugEvent, out bool passException)
	{
		switch (debugEvent.u.Exception.ExceptionRecord.ExceptionCode)
		{
			case ExceptionCode.EXCEPTION_BREAKPOINT:
				return OnBreakpoint(debugEvent, out passException);
			case ExceptionCode.EXCEPTION_SINGLE_STEP:
				return OnSingleStep(debugEvent, out passException);
			case ExceptionCode.CLRDBG_NOTIFICATION_EXCEPTION_CODE:
				passException = true;
				return true;
			default:
				using (var args = new ExceptionEventArgs(MemoryAccess, debugEvent))
				{
					Exception?.Invoke(this, args);
					passException = !args.Handled;
					return args.Continue;
				}
		}
	}

	protected virtual bool OnBreakpoint(DebugEvent debugEvent, out bool passException)
	{
		var address = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;

		if (!HitSystemBreakpoint)
		{
			//Enable the entry point breakpoint
			GetOrCreateBreakpoint(EntryPoint, nameof(BreakType.EntryPoint))
				.TryEnable();

			//The first breakpoint encountered after create process is the ntdll int3 (System Breakpoint)
			//The first breakpoint encountered after attaching to a process signals completion of attachment
			HitSystemBreakpoint = true;

			using var args = new BreakpointEventArgs(BreakType.System, debugEvent);
			Breakpoint?.Invoke(this, args);
			passException = !args.Handled;
			return args.Continue;
		}
		else if (Breakpoints.GetByAddress(address) is UserBreakpoint bp)
		{
			if (debugEvent.u.Exception.ExceptionRecord.ExceptionAddress == EntryPoint)
			{
				//memory breakpoint at entry point
				HasHitEntryPoint = true;
				Breakpoints.Remove(bp);
				using var args = new BreakpointEventArgs(BreakType.EntryPoint, debugEvent);
				args.Context.InstructionPointer--;
				Breakpoint?.Invoke(this, args);
				passException = !args.Handled;
				return args.Continue;
			}
			else
			{
				//User-set memory breakpoint
				bp.HitCount++;
				bp.TryDisable();
				using var args = new BreakpointEventArgs(BreakType.UserMemory, debugEvent, bp);
				args.Context.InstructionPointer--;
				Breakpoint?.Invoke(this, args);

				if (bp.AutoReset)
				{
					bp.NotifySingleStep = args.Context.EFlags.HasFlag(Flags.TF);
					args.Context.EFlags |= Flags.TF;
					//The next exception on this thread will be the single-step after this breakpoint
					BreaksToResume[args.ThreadId] = bp;
				}

				passException = !args.Handled;
				return args.Continue;
			}
		}
		else
		{
			using var args = new BreakpointEventArgs(BreakType.Other, debugEvent);
			args.Handled = false;
			Breakpoint?.Invoke(this, args);
			passException = !args.Handled;
			return args.Continue;
		}
	}

	protected virtual bool OnSingleStep(DebugEvent debugEvent, out bool passException)
	{
		using var args = new SingleStepEventArgs(debugEvent);

		if (BreaksToResume.Remove(debugEvent.ThreadId, out var bp))
		{
			//Reenable the memory breakpoint we just continued from
			bp.TryEnable();

			if (!bp.NotifySingleStep)
			{
				args.Context.EFlags &= ~Flags.TF;
				args.Context.EFlags |= Flags.RF;
				passException = false;
				return true;
			}
		}

		SingleStep?.Invoke(this, args);
		passException = !args.Handled;

		if (args.Handled)
		{
			args.Context.EFlags &= ~Flags.TF;
			args.Context.EFlags |= Flags.RF;
		}

		return args.Continue;
	}
}
