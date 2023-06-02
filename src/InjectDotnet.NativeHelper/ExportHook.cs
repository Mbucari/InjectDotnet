using InjectDotnet.NativeHelper.Native;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper;

/// <summary>
/// And instance of a hooked <see cref="NativeExport"/>
/// </summary>
public class ExportHook : NativeHook
{
	/// <summary>FunctionName of the module whose exported function will be replaced</summary>
	public string ExportingModuleName { get; }
	/// <summary>FunctionName of the exported function that's been hooked</summary>
	public string ExportedFunctionName { get; }

	private ExportHook(
		string exportingModuleName,
		string exportFunctionName,
		nint hExportFunc,
		nint pHookFunc)
		: base(hExportFunc, pHookFunc)
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
		if (hookFunction == 0 ||
			(export.Module.FileName ?? export.Module.ModuleName) is not string moduleName ||
			!NativeLibrary.TryLoad(moduleName, out var hModule)) return null;

		string exportFuncName;
		if (export.FunctionName is not null && NativeLibrary.TryGetExport(hModule, export.FunctionName, out nint hExportFunc))
			exportFuncName = export.FunctionName;
		else if ((hExportFunc = NativeMethods.GetProcAddress(hModule, export.Ordinal)) != 0)
			exportFuncName = $"@{export.Ordinal}";
		else
			return null;

		nint pHookFunc = AllocatePointerNearBase(hExportFunc);
		if (pHookFunc == 0) return null;

		*(nint*)pHookFunc = hookFunction;

		var hook = new ExportHook(Path.GetFileName(moduleName), exportFuncName, hExportFunc, pHookFunc);

		//Do not free hModule
		return hook.InstallHook() ? hook : null;
	}

	public override string ToString()
		=> $"{ExportingModuleName.RemoveDllExtension()}.{ExportedFunctionName}";
}
