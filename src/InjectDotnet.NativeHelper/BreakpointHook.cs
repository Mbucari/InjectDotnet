using InjectDotnet.NativeHelper.Breakpoints;
using InjectDotnet.NativeHelper.Minhook;
using InjectDotnet.NativeHelper.Native;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;

namespace InjectDotnet.NativeHelper;

/// <summary>
/// A hook of a native function that uses a hardware breakpoint to change the
/// execution address. Target instructions are not modified.
/// </summary>
/// /// <remarks>
/// NOTE: <see cref="BreakpointHook"/> cannot be debugged. The debugger will hang on the breakpoint and deadlock.
/// </remarks>
public class BreakpointHook : INativeHook
{
	public nint OriginalFunction => Trampoline.TrampolineAddress;
	public bool IsHooked
	{
		get => Breakpoint.Enabled is BreakEnabled.Local;
		set
		{
			if (value) InstallHook();
			else RemoveHook();
		}
	}
	public nint HookFunction => Breakpoint.ResumeIP;

	/// <summary>
	/// The <see cref="Native.Breakpoint"/> enabling this hook.
	/// </summary>
	protected virtual Breakpoint Breakpoint { get; set; }

	/// <summary>
	/// The <see cref="Minhook.Trampoline"/> that was written for this hook.
	/// </summary>
	protected virtual Trampoline Trampoline { get; set; }

	public bool IsDisposed { get; private set; }

	/// <summary>
	/// Pointer the the registered Vectored Exception Handler
	/// </summary>
	protected nint ExceptionHandler { get; set; }

	protected BreakpointHook(
		Trampoline trampoline,
		Breakpoint breakpoint)
	{
		Trampoline = trampoline;
		Breakpoint = breakpoint;

		//Setting the vectored exception handler to 'first' will cause
		//an ExecutionEngineException if the dotnet debugger is attached.
		//Note that hooking will not work properly if the handler is not
		//first because any of other application exception handlers may
		//change state in unpredictable ways.
		if (Debugger.IsAttached)
			throw new InvalidOperationException("Cannot use hardware breakpoint hooks while debugging the hooked process.");

		ExceptionHandler = NativeMethods.AddVectoredExceptionHandler(first: true, VectoredExceptionHandler);

		if (ExceptionHandler == 0)
			throw new Win32Exception($"{nameof(NativeMethods.AddVectoredExceptionHandler)} failed.");
	}

	public virtual bool RemoveHook()
	{
		if (IsDisposed)
			throw new ObjectDisposedException(nameof(JumpHook));

		Breakpoint.Enabled = BreakEnabled.Disabled;
		return Breakpoint.ThreadBreakpoints.SetDebugRegisters();
	}

	public virtual bool InstallHook()
	{
		if (IsDisposed)
			throw new ObjectDisposedException(nameof(JumpHook));

		Breakpoint.Enabled = BreakEnabled.Local;
		return Breakpoint.ThreadBreakpoints.SetDebugRegisters();
	}

	/// <summary>
	/// Create a <see cref="BreakpointHook"/> for a native function in this process.
	/// </summary>
	/// <param name="nativeFunctionEntryPoint">Entry point of an unmanaged function</param>
	/// <param name="hookFunction">Address of a delegate that will be called instead of <paramref name="nativeFunctionEntryPoint"/></param>
	/// <param name="threadId">The <see cref="ProcessThread.Id"/> of the execution thread to be hooked.</param>
	/// <param name="installAfterCreate">If true, hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
	/// <returns>A valid <see cref="BreakpointHook"/> if successful</returns>
	public unsafe static BreakpointHook? Create(
		nint nativeFunctionEntryPoint,
		nint hookFunction,
		int threadId,
		bool installAfterCreate = true)
	{
		if (nativeFunctionEntryPoint == 0 || hookFunction == 0) return null;

		NativeMethods.VirtualQuery(nativeFunctionEntryPoint, out var mbi, Unsafe.SizeOf<MemoryBasicInformation>());

		if (!(mbi.Protect
			is MemoryProtection.Execute
			or MemoryProtection.ExecuteRead
			or MemoryProtection.ExecuteReadWrite
			or MemoryProtection.ExecuteWriteCopy))
			return null;

		//Create the hardware breakpoint for the target function
		var hwBp
			= ThreadBreakpoints
			.GetThreadBreakpoints(threadId)
			?.FirstOrDefault(b => b.Address == 0);

		if (hwBp is null) return null;

		hwBp.ResumeIP = hookFunction;
		hwBp.Address = nativeFunctionEntryPoint;
		hwBp.Condition = BreakCondition.Execute;

		nint memoryBlock = NativeMemory.AllocateMemoryNearBase(nativeFunctionEntryPoint);

		if (memoryBlock == 0 || Trampoline.Create(nativeFunctionEntryPoint, memoryBlock) is not Trampoline trampoline)
			return null;

		var hook = new BreakpointHook(trampoline, hwBp);

		return !installAfterCreate || hook.InstallHook() ? hook : null;
	}

	private static unsafe int VectoredExceptionHandler(ref ExceptionPointers exceptionInfo)
	{
		const int EXCEPTION_CONTINUE_EXECUTION = -1;
		const int EXCEPTION_CONTINUE_SEARCH = 0;
		const uint STATUS_SINGLE_STEP = 0x80000004;

		if (exceptionInfo.ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
			return EXCEPTION_CONTINUE_SEARCH;

		var currentThread = NativeMethods.GetCurrentThreadId();

		if (ThreadBreakpoints.GetThreadBreakpoints(currentThread)
			is not ThreadBreakpoints threadBP)
			return EXCEPTION_CONTINUE_SEARCH;

		var regIdx = exceptionInfo.ContextRecord->Dr.DetectedBreakCondition;

		if (regIdx is DebugRegister.None)
			return EXCEPTION_CONTINUE_SEARCH;

		var bp = threadBP[regIdx];

		// Set the resume flag before continuing execution
		exceptionInfo.ContextRecord->EFlags |= 0x10000;

		//Set the location to resume execution
		if (bp.ResumeIP != 0)
			exceptionInfo.ContextRecord->InstructionPointer = bp.ResumeIP;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	public void Dispose()
	{
		if (!IsDisposed)
		{
			Breakpoint.Enabled = 0;
			Breakpoint.Address = 0;
			Breakpoint.Condition = 0;
			Breakpoint.Length = 0;
			Breakpoint.ThreadBreakpoints.SetDebugRegisters();
			NativeMethods.RemoveVectoredExceptionHandler(ExceptionHandler);
			NativeMethods.VirtualFree(Trampoline.TrampolineAddress, 0, FreeType.Release);
			ExceptionHandler = 0;
			IsDisposed = true;
		}
	}
}
