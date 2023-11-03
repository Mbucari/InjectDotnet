using InjectDotnet.NativeHelper.Minhook;
using InjectDotnet.NativeHelper.Native;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper;

/// <summary>An instance of a native function memory-based jmp hook</summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
unsafe public class JumpHook : INativeHook
{
	public nint OriginalFunction { get; }
	/// <summary>Name of the module containing function being hooked</summary>
	public string? ModuleName { get; }
	/// <summary>Name of the exported function that's being hooked</summary>
	public string? FunctionName { get; }
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
	public bool IsHooked
	{
		get => isHooked;
		set
		{
			if (value) InstallHook();
			else RemoveHook();
		}
	}
	public bool IsDisposed { get; private set; }

	private bool isHooked;
	/// <summary>
	/// The trampoline that was written for this hook.
	/// </summary>
	private readonly Trampoline? m_Trampoline;
	/// <summary>
	/// Address of the instruction that jumps to <see cref="HookFunction"/>
	/// </summary>
	private readonly nint m_pHookJump;
	/// <summary>
	/// If <see cref="HasTrampoline"/> is false, contains the first 8 bytes of <see cref="OriginalFunction"/>
	/// </summary>
	private readonly ulong m_OriginalEpBytes;

	protected JumpHook(
		nint originalFunc,
		nint hookFunction,
		nint memoryBlock,
		string? moduleName,
		string? functionName)
	{
		HookFunction = hookFunction;
		MemoryBlock = memoryBlock;
		ModuleName = moduleName;
		FunctionName = functionName;

		//Hook status is set at base of block
		memoryBlock++;
#if X64
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
#elif X86
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
#endif
		if ((m_Trampoline = Trampoline.Create(originalFunc, m_pHookJump + sizeof(JMP_ABS))) is not null)
		{
			OriginalFunction = m_Trampoline.TrampolineAddress;

			//Overwrite the target's entry point with a jump the pop eax/rax instruction at MemoryBlock + 1
			MemoryProtection oldProtect;
			NativeMethods.VirtualProtect(originalFunc, sizeof(JMP_REL), MemoryProtection.ExecuteReadWrite, &oldProtect);
			//Store the original instructions so hook can be disposed
			m_OriginalEpBytes = *(ulong*)originalFunc;
			//Write jump to trampoline hook stub
			*(JMP_REL*)originalFunc = new JMP_REL(MemoryBlock + 1, originalFunc);
			//Restore IAT's protection
			NativeMethods.VirtualProtect(originalFunc, sizeof(JMP_REL), oldProtect, &oldProtect);
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
		if (IsDisposed)
			throw new ObjectDisposedException(nameof(JumpHook));

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
		if (IsDisposed)
			throw new ObjectDisposedException(nameof(JumpHook));

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
	/// Create a <see cref="JumpHook"/> for a native function in this process.
	/// </summary>
	/// <param name="nativeFunctionEntryPoint">Entry point of an unmanaged function</param>
	/// <param name="hookFunction">Address of a delegate that will be called instead of <paramref name="nativeFunctionEntryPoint"/></param>
	/// <param name="installAfterCreate">If true, hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
	/// <returns>A valid <see cref="JumpHook"/> if successful</returns>
	public static JumpHook? Create(
		nint nativeFunctionEntryPoint,
		nint hookFunction,
		bool installAfterCreate = true,
		string? moduleName = null,
		string? functionName = null)
	{
		if (nativeFunctionEntryPoint == 0 || hookFunction == 0) return null;

		NativeMethods.VirtualQuery(nativeFunctionEntryPoint, out var mbi, Unsafe.SizeOf<MemoryBasicInformation>());

		if (!(mbi.Protect
			is MemoryProtection.Execute
			or MemoryProtection.ExecuteRead
			or MemoryProtection.ExecuteReadWrite
			or MemoryProtection.ExecuteWriteCopy))
			return null;

		nint memoryBlock = NativeMemory.AllocateMemoryNearBase(nativeFunctionEntryPoint);
		if (memoryBlock == 0) return null;

		var hook = new JumpHook(nativeFunctionEntryPoint, hookFunction, memoryBlock, moduleName, functionName);

		return !installAfterCreate || hook.InstallHook() ? hook : null;
	}

	/// <summary>
	/// Create an <see cref="JumpHook"/> for a native function exported by a native library in this process.
	/// </summary>
	/// <param name="export">The exported function to be hooked.</param>
	/// <param name="hookFunction">Pointer to a delegate that will be called instead of <see cref="NativeExport.FunctionName"/></param>
	/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
	/// <returns>A valid <see cref="JumpHook"/> if successful</returns>
	unsafe public static JumpHook? Create(
		NativeExport export,
		nint hookFunction,
		bool installAfterCreate = true)
	{
		if (hookFunction == 0 ||
			(export.Module.FileName ?? export.Module.ModuleName) is not string moduleName ||
			!NativeLibrary.TryLoad(moduleName, out var hModule)) return null;

		string exportFuncName;
		if (export.FunctionName is not null && NativeLibrary.TryGetExport(hModule, export.FunctionName, out nint originalFunc))
			exportFuncName = export.FunctionName;
		else if ((originalFunc = NativeMethods.GetProcAddress(hModule, export.Ordinal)) != 0)
			exportFuncName = $"@{export.Ordinal}";
		else
			return null;

		//Do not free hModule
		return Create(originalFunc, hookFunction, installAfterCreate, Path.GetFileName(moduleName), exportFuncName);
	}

	[DebuggerBrowsable(DebuggerBrowsableState.Never)]
	protected virtual string DebuggerDisplay => $"{ToString()}, {nameof(IsHooked)} = {IsHooked}";

	public override string ToString() => $"{OriginalFunction.ToString($"x{IntPtr.Size}")}";

	public virtual void Dispose()
	{
		if (!IsDisposed)
		{
			if (HasTrampoline)
			{
				MemoryProtection oldProtect;
				NativeMethods.VirtualProtect(m_Trampoline!.TargetAddress, sizeof(ulong), MemoryProtection.ExecuteReadWrite, &oldProtect);
				*(ulong*)m_Trampoline!.TargetAddress = m_OriginalEpBytes;
				//Restore IAT's protection
				NativeMethods.VirtualProtect(m_Trampoline!.TargetAddress, sizeof(ulong), oldProtect, &oldProtect);
			}
			else
				RemoveHook();

			NativeMethods.VirtualFree(MemoryBlock, 0, FreeType.Release);
			isHooked = false;
			IsDisposed = true;
		}
	}
}
