using InjectDotnet.NativeHelper.Native;
using System.Diagnostics;

namespace InjectDotnet.NativeHelper;

/// <summary>And instance of a hooked native function</summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public class NativeHook : INativeHook
{
	private bool isHooked;
	public nint OriginalFunction { get; }
	public bool IsHooked
	{
		get => isHooked;
		set
		{
			if (value) InstallHook();
			else RemoveHook();
		}
	}
	/// <summary>Original first 8 bytes of <see cref="OriginalFunction"/>'s instructions
	/// that was replaced with a jump to the hook function</summary>
	protected ulong OriginalCode { get; }
	/// <summary>Pointer to the unmanaged delegate that is hooking <see cref="OriginalFunction"/></summary>
	protected nint HookFunctionPointer { get; }

	unsafe protected NativeHook(
		nint hOriginalFunc,
		nint pHookFunc)
	{
		OriginalFunction = hOriginalFunc;
		HookFunctionPointer = pHookFunc;

		//Backup the first 8 bytes of the original export function's code. 
		OriginalCode = *(ulong*)hOriginalFunc;
	}

	unsafe public bool InstallHook()
	{
		lock (this)
		{
			if (IsHooked) return false;

			//32bit offset from RIP in x64, disp32 in x86
			var jmpOperand
				= Environment.Is64BitProcess
				? (uint)(HookFunctionPointer - OriginalFunction - 6)
				: (uint)HookFunctionPointer;

			MemoryProtection oldProtect;
			NativeMethods.VirtualProtect(OriginalFunction, sizeof(nint), MemoryProtection.ExecuteReadWrite, &oldProtect);
			*(ushort*)OriginalFunction = 0x25ff; //long jmp
			*(uint*)(OriginalFunction + 2) = jmpOperand;
			//Restore IAT's protection
			NativeMethods.VirtualProtect(OriginalFunction, sizeof(nint), oldProtect, &oldProtect);

			return isHooked = true;
		}
	}

	unsafe public bool RemoveHook()
	{
		lock (this)
		{
			if (!IsHooked) return false;

			MemoryProtection oldProtect;
			NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), MemoryProtection.ExecuteReadWrite, &oldProtect);
			*(ulong*)OriginalFunction = OriginalCode;
			//Restore IAT's protection
			NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), oldProtect, &oldProtect);

			return !(isHooked = false);
		}
	}

	/// <summary>
	/// Create a <see cref="NativeHook"/> for a native function in this process.
	/// </summary>
	/// <param name="nativeFunctionEntryPoint"></param>
	/// <param name="hookFunction"></param>
	/// <returns>A valid <see cref="NativeHook"/> if successful</returns>
	unsafe public static NativeHook? Create(
		nint nativeFunctionEntryPoint,
		nint hookFunction)
	{
		if (nativeFunctionEntryPoint == 0 || hookFunction == 0) return null;

		nint pHookFunc = AllocatePointerNearBase(nativeFunctionEntryPoint);
		if (pHookFunc == 0) return null;

		*(nint*)pHookFunc = hookFunction;

		var hook = new NativeHook(nativeFunctionEntryPoint, pHookFunc);

		return hook.InstallHook() ? hook : null;
	}

	[DebuggerBrowsable(DebuggerBrowsableState.Never)]
	private string DebuggerDisplay => $"{ToString()}, {nameof(IsHooked)} = {IsHooked}";

	public override string ToString() => $"{OriginalFunction.ToString($"x{IntPtr.Size}")}";

	/// <summary>
	/// Allocate some memory to store a pointer to the hook function. The pointer must be in
	/// range of the exported function so that it can be reached with a long jmp. The Maximum
	/// distance of a long jump offset size is 32 bits in both x86 and x64. 
	/// </summary>
	/// <param name="baseAddress"></param>
	/// <returns>A pointer to the beginning of the free memory block</returns>
	protected static unsafe nint AllocatePointerNearBase(nint baseAddress)
	{
		nint minSize = sizeof(nint);
		var pHookFn = NativeMemory.FirstFreeAddress(baseAddress, ref minSize);
		if (pHookFn == 0 || minSize == 0 || pHookFn - baseAddress > uint.MaxValue) return 0;

		return NativeMethods.VirtualAlloc(pHookFn, sizeof(nint), AllocationType.ReserveCommit, MemoryProtection.ReadWrite);
	}
}
