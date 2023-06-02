﻿using InjectDotnet.NativeHelper.Native;

namespace InjectDotnet.NativeHelper;

/// <summary>And instance of a hooked native function</summary>
public class NativeHook : INativeHook
{
	public nint OriginalFunction { get; private set; }
	public bool IsHooked { get; private set; }
	/// <summary>Original first 8 bytes of <see cref="OriginalFunction"/>'s instructions
	/// that was replaced with a jump to the hook function</summary>
	protected ulong OriginalCode { get; }
	/// <summary>Pointer to the unmanaged delegate that is hooking <see cref="OriginalFunction"/></summary>
	protected nint HookFunctionPointer { get; }

	protected NativeHook(
		nint hExportFn,
		nint hookFunctionPointer,
		ulong originalCode)
	{
		OriginalFunction = hExportFn;
		HookFunctionPointer = hookFunctionPointer;
		OriginalCode = originalCode;
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

			return IsHooked = true;
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

			return !(IsHooked = false);
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

		//Allocate some memory to store a pointer to the hook function. The pointer must be in
		//range of the exported function so that it can be reached with a long jmp. The Maximum
		//distance of a long jump offset size is 32 bits in both x86 and x64.
		nint minFreeSize = sizeof(nint);
		var pHookFn = FirstFreeAddress(nativeFunctionEntryPoint, ref minFreeSize);
		if (pHookFn == 0 || minFreeSize == 0 || pHookFn - nativeFunctionEntryPoint > uint.MaxValue) return null;

		pHookFn = NativeMethods.VirtualAlloc(pHookFn, sizeof(nint), AllocationType.ReserveCommit, MemoryProtection.ReadWrite);
		if (pHookFn == 0) return null;

		*(nint*)pHookFn = hookFunction;

		//Backup the first 8 bytes of the original export function's code. 
		ulong originalCode = *(ulong*)nativeFunctionEntryPoint;

		var hook = new NativeHook(nativeFunctionEntryPoint, pHookFn, originalCode);

		//Do not free hModule
		return hook.InstallHook() ? hook : null;
	}

	/// <summary>
	/// Find the first free region of memory after <paramref name="baseAddress"/>
	/// </summary>
	/// <param name="baseAddress">The virtual memory address to begin searching for free memory</param>
	/// <param name="minFreeSize">Size of the free memory block</param>
	/// <returns>Base address of the free memory block</returns>
	protected static nint FirstFreeAddress(nint baseAddress, ref nint minFreeSize)
	{
		var minSize = minFreeSize;
		foreach (var mbi in NativeMemory.GetMemoryInfo(baseAddress).Where(m => m.State == MemoryState.MemFree))
		{
			minFreeSize = mbi.RegionSize - (mbi.BaseAddressRoundedUp - mbi.BaseAddress);

			if (minFreeSize > minSize) return mbi.BaseAddressRoundedUp;
		}
		minFreeSize = 0;
		return 0;
	}
}