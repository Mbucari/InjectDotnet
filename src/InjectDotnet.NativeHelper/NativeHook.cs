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

		//Hook status is set at base of block
		memoryBlock++;
		if (Environment.Is64BitProcess)
		{
			//push rax
			*(byte*)memoryBlock = 0x50;
			//mov al, [memoryBlock]
			*(ushort*)(memoryBlock += sizeof(byte)) = 0x058a;
			*(int*)(memoryBlock += sizeof(ushort)) = -8;
			//test al,al
			*(ushort*)(memoryBlock += sizeof(int)) = 0xc084;
			//pop rax
			*(byte*)(memoryBlock += sizeof(ushort)) = 0x58;
			//je over hook to trampoline
			*(byte*)(memoryBlock += sizeof(byte)) = 0x74;
			*(byte*)(memoryBlock += sizeof(byte)) = (byte)sizeof(JMP_ABS);

			m_pHookJump = memoryBlock + sizeof(byte);
			*(JMP_ABS*)m_pHookJump = new JMP_ABS(hookFunction);
		}
		else
		{
			//push eax
			*(byte*)memoryBlock = 0x50;
			//mov al, [memoryBlock]
			*(byte*)(memoryBlock += sizeof(byte)) = 0xa0;
			*(uint*)(memoryBlock += sizeof(byte)) = (uint)memoryBlock;
			//test al,al
			*(ushort*)(memoryBlock += sizeof(uint)) = 0xc084;
			//pop eax
			*(byte*)(memoryBlock += sizeof(ushort)) = 0x58;
			//je over hook to trampoline
			*(byte*)(memoryBlock += sizeof(byte)) = 0x74;
			*(byte*)(memoryBlock += sizeof(byte)) = (byte)sizeof(JMP_ABS);

			m_pHookJump = memoryBlock + sizeof(byte);
			*(JMP_ABS*)m_pHookJump = new JMP_ABS(hookFunction, (uint)m_pHookJump);
		}

		if ((m_Trampoline = Trampoline.Create(originalFunc, m_pHookJump + sizeof(JMP_ABS))) is not null)
		{
			OriginalFunction = m_Trampoline.TrampolineAddress;

			//Overwrite the target's entry point with a jump the pop eax/rax instruction at MemoryBlock + 1
			MemoryProtection oldProtect;
			NativeMethods.VirtualProtect(originalFunc, sizeof(nint), MemoryProtection.ExecuteReadWrite, &oldProtect);
			*(JMP_REL*)originalFunc = new JMP_REL(MemoryBlock + 1, originalFunc);
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

	public virtual bool InstallHook()
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
				if (!NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), MemoryProtection.ExecuteReadWrite, &oldProtect))
					return false;

				*(JMP_REL*)OriginalFunction = new JMP_REL(m_pHookJump, OriginalFunction);

				if (!NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), oldProtect, &oldProtect))
					return false;
			}
			return isHooked = true;
		}
	}

	public virtual bool RemoveHook()
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
				if (!NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), MemoryProtection.ExecuteReadWrite, &oldProtect))
					return false;

				*(ulong*)OriginalFunction = m_OriginalEpBytes;

				if (!NativeMethods.VirtualProtect(OriginalFunction, sizeof(ulong), oldProtect, &oldProtect))
					return false;
			}

			return !(isHooked = false);
		}
	}

	/// <summary>
	/// Create a <see cref="NativeHook"/> for a native function in this process.
	/// </summary>
	/// <param name="nativeFunctionEntryPoint">Entry point of an unmanaged function</param>
	/// <param name="hookFunction">Address of a delegate that will be called instead of <paramref name="nativeFunctionEntryPoint"/></param>
	/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
	/// <returns>A valid <see cref="NativeHook"/> if successful</returns>
	public static NativeHook? Create(
		nint nativeFunctionEntryPoint,
		nint hookFunction,
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

		nint memoryBlock = AllocateMemoryNearBase(nativeFunctionEntryPoint);
		if (memoryBlock == 0) return null;

		var hook = new NativeHook(nativeFunctionEntryPoint, memoryBlock, hookFunction);

		return !installAfterCreate || hook.InstallHook() ? hook : null;
	}

	[DebuggerBrowsable(DebuggerBrowsableState.Never)]
	protected virtual string DebuggerDisplay => $"{ToString()}, {nameof(IsHooked)} = {IsHooked}";

	public override string ToString() => $"{OriginalFunction.ToString($"x{IntPtr.Size}")}";

	/// <summary>
	/// Allocate some memory to store a pointer to the hook function. The pointer must be in
	/// range of the exported function so that it can be reached with a long jmp. The Maximum
	/// distance of a long jump offset size is 32 bits in both x86 and x64. 
	/// </summary>
	/// <param name="baseAddress">Address in virtual to begin searching for a free memory block</param>
	/// <returns>A pointer to the beginning of the free memory block</returns>
	protected static nint AllocateMemoryNearBase(nint baseAddress)
	{
		nint minSize = sizeof(nint);
		var pHookFn = NativeMemory.FirstFreeAddress(baseAddress, ref minSize);
		if (pHookFn == 0 || minSize == 0 || pHookFn - baseAddress > uint.MaxValue) return 0;
		
		return NativeMethods.VirtualAlloc(
			pHookFn,
			(nint)MemoryBasicInformation.SystemInfo.PageSize,
			AllocationType.ReserveCommit,
			MemoryProtection.ExecuteReadWrite);
	}
}
