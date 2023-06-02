using InjectDotnet.NativeHelper.Native;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper;

/// <summary>
/// And instance of a hooked <see cref="NativeExport"/>
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public class ExportHook : NativeHook
{
	/// <summary>FunctionName of the module whose exported function will be replaced</summary>
	public string ExportingModuleName { get; }
	/// <summary>FunctionName of the exported function that's been hooked</summary>
	public string ExportedFunctionName { get; }

	private ExportHook(
		string exportingModuleName,
		string exportFunctionName,
		nint hExportFn,
		nint hookFunctionPointer,
		ulong originalCode) : base(hExportFn, hookFunctionPointer, originalCode)
	{
		ExportingModuleName = exportingModuleName;
		ExportedFunctionName = exportFunctionName;
	}

	/// <summary>
	/// Create a <see cref="ExportHook"/> for a native function exported by a native library in this process.
	/// </summary>
	/// <param name="export">The import in the current process to be hooked.</param>
	/// <param name="hookFunction">Pointer to a managed delegate that will be called instead of <paramref name="exportedFunctionName"/></param>
	/// <remarks>
	/// While imports can be hooked by changing the function pointer in the modules IAT, exports can't be hooked so simply.
	/// A module's Export Address Table is read only once when the image is bound, so changing the function's address in
	/// the EAT after the PE is loaded will have no effect. Instead, Hooking is accomplished by replacing the first 6
	/// bytes of the function with a jump instruction to the hook. This is destructive and means that the original function
	/// cannot be called until the hook is removed.
	/// <br /><br />
	/// If the export points to an entry in a jump table, you may work around this limitation by creating a delegate for the
	/// original function at the target of that jump. Many winapi functions exported by kernel32, for instance, are jumps to
	/// identically named functions in kernelbase.
	/// </remarks>
	/// <returns>A valid <see cref="ExportHook"/> if successful</returns>
	unsafe public static ExportHook? Create(
		NativeExport export,
		nint hookFunction)
	{
		if (hookFunction == 0 || (export.Module.FileName ?? export.Module.ModuleName) is not string moduleName) return null;

		if (!NativeLibrary.TryLoad(moduleName, out var hModule))
			return null;

		string funcName;
		if (export.FunctionName is not null && NativeLibrary.TryGetExport(hModule, export.FunctionName, out nint hExportFn))
			funcName = export.FunctionName;
		else if ((hExportFn = NativeMethods.GetProcAddress(hModule, export.Ordinal)) != 0)
			funcName = $"#{export.Ordinal}";
		else
			return null;

		//Backup the first 8 bytes of the original export function's code. 
		ulong originalCode = *(ulong*)hExportFn;

		//Allocate some memory to store a pointer to the hook function. The pointer must be in
		//range of the exported function so that it can be reached with a long jmp. The Maximum
		//distance of a long jump offset size is 32 bits in both x64 and x64.
		var pHookFn = FirstFreeAddress(hModule, out _);
		pHookFn = NativeMethods.VirtualAlloc(pHookFn, sizeof(nint), AllocationType.ReserveCommit, MemoryProtection.ReadWrite);

		if (pHookFn == 0 || pHookFn - hModule > uint.MaxValue) return null;

		*(nint*)pHookFn = hookFunction;

		var hook = new ExportHook(Path.GetFileName(moduleName), funcName, hExportFn, pHookFn, originalCode);

		//Do not free hModule
		return hook.InstallHook() ? hook : null;
	}

	[DebuggerBrowsable(DebuggerBrowsableState.Never)]
	private string DebuggerDisplay => $"{ToString()}, {nameof(IsHooked)} = {IsHooked}";
	public override string ToString()
	{
		return $"{ExportingModuleName.RemoveDllExtension()}.{ExportedFunctionName}()";
	}
}
