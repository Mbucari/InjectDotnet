using InjectDotnet.NativeHelper.Minhook;
using InjectDotnet.NativeHelper.Native;
using System.Diagnostics;

namespace InjectDotnet.NativeHelper;

/// <summary>An instance of a hooked native function</summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
unsafe public class NativeHook : INativeHook
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

	/// <summary>Address of the delegate that is hooking <see cref="OriginalFunction"/></summary>
	public nint HookFunction { get; }
	/// <summary>
	/// Whether the hook was placed with a trampoline. If true, <see cref="OriginalFunction"/> may be
	/// called while the hook is installed and Removing/Installing the hook is thread-safe. If false,
	/// the hook must be removed before making calls to <see cref="OriginalFunction"/> and removing/
	/// installing the hook is not thread safe.
	/// </summary>
	public bool HasTrampoline => m_Trampoline is not null;

	/// <summary>
	/// E/W/R memory located within 2^32 bytes of <see cref="OriginalFunction"/> that stores the hook jump instruction and trampoline
	/// </summary>
	public nint MemoryBlock { get; }
	/// <summary>
	/// The trampoline that was written for this hook.
	/// </summary>
	private readonly Trampoline? m_Trampoline;
	/// <summary>
	/// Address of the instruction that jumps to <see cref="HookFunction"/>
	/// </summary>
	private readonly nint m_pHookJump;
	/// <summary>
	/// If <see cref="HasTrampoline"/> is false, contains thefirst 8 bytes of <see cref="OriginalFunction"/>
	/// </summary>
	private readonly ulong m_OriginalEpBytes;

	protected NativeHook(
		nint originalFunc,
		nint hookFunction,
		nint memoryBlock)
	{
		HookFunction = hookFunction;
		MemoryBlock = memoryBlock;

		if (Environment.Is64BitProcess)
		{
			//push rax
			*(byte*)(memoryBlock + 1) = 0x50;
			//mov al, [memoryBlock]
			*(ushort*)(memoryBlock + 2) = 0x058a;
			*(int*)(memoryBlock + 4) = -8;
			//test al,al
			*(ushort*)(memoryBlock + 8) = 0xc084;
			//pop rax
			*(byte*)(memoryBlock + 10) = 0x58;
			//je over hook to trampoline
			*(byte*)(memoryBlock + 11) = 0x74;
			*(byte*)(memoryBlock + 12) = (byte)(6 + sizeof(nint));

			m_pHookJump = memoryBlock + 13;
			//long jmp to the hook
			*(ushort*)m_pHookJump = 0x25ff;
			*(uint*)(m_pHookJump + 2) = 0;
			*(nint*)(m_pHookJump + 6) = hookFunction;
		}
		else
		{
			//push eax
			*(byte*)(memoryBlock + 1) = 0x50;
			//mov al, [memoryBlock]
			*(byte*)(memoryBlock + 2) = 0xa0;
			*(uint*)(memoryBlock + 3) = (uint)memoryBlock;
			//test al,al
			*(ushort*)(memoryBlock + 7) = 0xc084;
			//pop eax
			*(byte*)(memoryBlock + 9) = 0x58;
			//je over hook to trampoline
			*(byte*)(memoryBlock + 10) = 0x74;
			*(byte*)(memoryBlock + 11) = (byte)(6 + sizeof(nint));

			m_pHookJump = memoryBlock + 12;
			//long jmp to the hook
			*(ushort*)m_pHookJump = 0x25ff;
			*(uint*)(m_pHookJump + 2) = (uint)m_pHookJump + 6;
			*(nint*)(m_pHookJump + 6) = hookFunction;
		}

		if (Trampoline.Create(originalFunc, m_pHookJump + 6 + sizeof(nint)) is Trampoline trampoline)
		{
			m_Trampoline = trampoline;
			OriginalFunction = trampoline.TrampolineAddress;

			//Overwrite the target's entry point with a jump the pop eax/rax instruction at MemoryBlock + 1
			MemoryProtection oldProtect;
			NativeMethods.VirtualProtect(originalFunc, sizeof(nint), MemoryProtection.ExecuteReadWrite, &oldProtect);
			*(byte*)originalFunc = 0xE9; //jmp rel
			*(uint*)(originalFunc + 1) = (uint)(memoryBlock - originalFunc + 1 - 5 /* jump instruction size*/);
			//Restore IAT's protection
			NativeMethods.VirtualProtect(originalFunc, sizeof(nint), oldProtect, &oldProtect);
		}
		else
		{
			//Failed to create a trampoline, so store the first 8 bytes of the function
			//so users may install/remove the hook at will
			OriginalFunction = originalFunc;
			m_OriginalEpBytes = *(ulong*)originalFunc;
		}
	}

	public bool InstallHook()
	{
		lock (this)
		{
			if (IsHooked) return false;

			if (HasTrampoline)
			{
				//Trampoline is in use, so hooking/unhooking is done by flipping the first byte at MemoryBlock
				*(byte*)MemoryBlock = 1;
			}
			else
			{
				//Trampoline not in use, so overwrite target function's entry point with a jump the the jump to the hook
				MemoryProtection oldProtect;
				NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), MemoryProtection.ExecuteReadWrite, &oldProtect);
				*(ulong*)OriginalFunction = ((ulong)(m_pHookJump - OriginalFunction - 5) << 8) | 0xE9;
				//Restore IAT's protection
				NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), oldProtect, &oldProtect);
			}
			return isHooked = true;
		}
	}

	public bool RemoveHook()
	{
		lock (this)
		{
			if (!IsHooked) return false;

			if (HasTrampoline)
			{
				//Trampoline is in use, so hooking/unhooking is done by flipping the first byte at MemoryBlock
				*(byte*)MemoryBlock = 0;
			}
			else
			{
				//Trampoline not in use, so replace target function's original entry point bytes
				MemoryProtection oldProtect;
				NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), MemoryProtection.ExecuteReadWrite, &oldProtect);
				*(ulong*)OriginalFunction = m_OriginalEpBytes;
				//Restore IAT's protection
				NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), oldProtect, &oldProtect);
			}

			return !(isHooked = false);
		}
	}

	/// <summary>
	/// Create a <see cref="NativeHook"/> for a native function in this process.
	/// </summary>
	/// <param name="nativeFunctionEntryPoint">Entry point of an unmanaged function</param>
	/// <param name="hookFunction">Address of a delegate that will be called instead of <paramref name="nativeFunctionEntryPoint"/></param>
	/// <returns>A valid <see cref="NativeHook"/> if successful</returns>
	public static NativeHook? Create(
		nint nativeFunctionEntryPoint,
		nint hookFunction)
	{
		if (nativeFunctionEntryPoint == 0 || hookFunction == 0) return null;

		NativeMethods.VirtualQuery(nativeFunctionEntryPoint, out var mbi, MemoryBasicInformation.NativeSize);

		if (mbi.Protect
			is not MemoryProtection.Execute
			and not MemoryProtection.ExecuteRead
			and not MemoryProtection.ExecuteReadWrite
			and not MemoryProtection.ExecuteWriteCopy)
			return null;

		nint memoryBlock = AllocatePointerNearBase(nativeFunctionEntryPoint);
		if (memoryBlock == 0) return null;

		var hook = new NativeHook(nativeFunctionEntryPoint, memoryBlock, hookFunction);

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
	/// <param name="baseAddress">Address in virtual to begin searching for a free memory block</param>
	/// <returns>A pointer to the beginning of the free memory block</returns>
	protected static nint AllocatePointerNearBase(nint baseAddress)
	{
		nint minSize = sizeof(nint);
		var pHookFn = NativeMemory.FirstFreeAddress(baseAddress, ref minSize);
		if (pHookFn == 0 || minSize == 0 || pHookFn - baseAddress > uint.MaxValue) return 0;

		return NativeMethods.VirtualAlloc(pHookFn, sizeof(nint), AllocationType.ReserveCommit, MemoryProtection.ExecuteReadWrite);
	}
}
