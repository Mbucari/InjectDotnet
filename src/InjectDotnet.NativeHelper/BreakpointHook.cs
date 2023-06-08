using InjectDotnet.NativeHelper.Minhook;
using InjectDotnet.NativeHelper.Native;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

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
	/// The <see cref="NativeHelper.Breakpoint"/> enabling this hook.
	/// </summary>
	protected virtual Breakpoint Breakpoint { get; set; }

	/// <summary>
	/// The <see cref="Minhook.Trampoline"/> that was written for this hook.
	/// </summary>
	protected virtual Trampoline Trampoline { get; set; }

	protected BreakpointHook(
		Trampoline trampoline,
		Breakpoint breakpoint)
	{
		Trampoline = trampoline;
		Breakpoint = breakpoint;
	}

	public virtual bool RemoveHook()
	{
		Breakpoint.Enabled = BreakEnabled.Disabled;
		return Breakpoint.ThreadBreakpoints.SetDebugRegisters();
	}

	public virtual bool InstallHook()
	{
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

		NativeMethods.VirtualQuery(nativeFunctionEntryPoint, out var mbi, MemoryBasicInformation.NativeSize);

		if (!(mbi.Protect
			is MemoryProtection.Execute
			or MemoryProtection.ExecuteRead
			or MemoryProtection.ExecuteReadWrite
			or MemoryProtection.ExecuteWriteCopy))
			return null;

		//Create the hardware breakpoint for the target function
		var hwBp
			= HardwareBreakpoints
			.GetThreadBreakpoints(threadId)
			?.Breakpoints
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

	static BreakpointHook()
	{
		SetVectoredExceptionHandler();
	}

	/// <summary>
	/// Pointer the the registered Vectored Exception Handler
	/// </summary>
	protected static nint ExceptionHandler { get; set; }

	/// <summary>
	/// Sets a vectored exception handler for the process;
	/// </summary>
	/// <returns>Success</returns>
	unsafe public static bool SetVectoredExceptionHandler()
	{
		//Setting the vectored exception handler to 'first' will cause an
		//ExecutionEngineException if the dotnet debugger is attached.
		//Note that hooking will not work properly is the handler is not
		//first because any of other application exception handlers may
		//change state in unpredictable ways.
		uint first = Debugger.IsAttached ? 0u : 1;

		if (ExceptionHandler != 0)
		{
			if (!NativeMethods.RemoveVectoredExceptionHandler(ExceptionHandler))
				return false;

			ExceptionHandler = 0;
		}

		ExceptionHandler = NativeMethods.AddVectoredExceptionHandler(first, &VectoredExceptionHandler);

		return ExceptionHandler != 0;
	}


	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	unsafe delegate int ExceptionHandlerDelegate(ExceptionPointers* exceptionInfo);


	private const int EXCEPTION_CONTINUE_EXECUTION = -1;
	private const int EXCEPTION_CONTINUE_SEARCH = 0;
	private const uint STATUS_SINGLE_STEP = 0x80000004;

	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	private static unsafe int VectoredExceptionHandler(ExceptionPointers* exceptionInfo)
	{
		if (exceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
			return EXCEPTION_CONTINUE_SEARCH;

		var currentThread = NativeMethods.GetCurrentThreadId();

		if (HardwareBreakpoints.GetThreadBreakpoints(currentThread)
			is not ThreadBreakpoints threadBP)
			return EXCEPTION_CONTINUE_SEARCH;

		int regIdx = exceptionInfo->ContextRecord->Dr.DetectedBreakCondition;

		if (regIdx == -1)
			return EXCEPTION_CONTINUE_SEARCH;

		var bp = threadBP.Breakpoints[regIdx];

		// Set the resume flag before continuing execution
		exceptionInfo->ContextRecord->EFlags |= 0x10000;

		//Set the location to resume execution
		if (bp.ResumeIP != 0)
			exceptionInfo->ContextRecord->InstructionPointer = bp.ResumeIP;

		if (Debugger.IsAttached)
		{
			//Cannot properly resume execution from STATUS_SINGLE_STEP while being debugged,
			//so disable the breakpoint before continuing execution.
			bp.Enabled = BreakEnabled.Disabled;
			exceptionInfo->ContextRecord->Dr.SetEnabled(regIdx, BreakEnabled.Disabled);
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}
}
