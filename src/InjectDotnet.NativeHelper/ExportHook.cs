using InjectDotnet.NativeHelper.Native;
using System.IO;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper;

/// <summary>
/// An instance of a hooked <see cref="NativeExport"/>
/// </summary>
public class ExportHook : NativeHook
{
	/// <summary>Name of the module whose exported function is being hooked</summary>
	public string ExportingModuleName { get; }
	/// <summary>Name of the exported function that's being hooked</summary>
	public string ExportedFunctionName { get; }

	protected ExportHook(
		string exportingModuleName,
		string exportFunctionName,
		nint originalFunc,
		nint hookFunction,
		nint memoryBlock)
		: base(originalFunc, hookFunction, memoryBlock)
	{
		ExportingModuleName = exportingModuleName;
		ExportedFunctionName = exportFunctionName;
	}

	/// <summary>
	/// Create an <see cref="ExportHook"/> for a native function exported by a native library in this process.
	/// </summary>
	/// <param name="export">The exported function to be hooked.</param>
	/// <param name="hookFunction">Pointer to a delegate that will be called instead of <see cref="NativeExport.FunctionName"/></param>
	/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
	/// <returns>A valid <see cref="ExportHook"/> if successful</returns>
	unsafe public static ExportHook? Create(
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

		nint memBlock = AllocateMemoryNearBase(originalFunc);
		if (memBlock == 0) return null;

		var hook = new ExportHook(Path.GetFileName(moduleName), exportFuncName, originalFunc, hookFunction, memBlock);

		//Do not free hModule
		return !installAfterCreate || hook.InstallHook() ? hook : null;
	}

	public override string ToString()
		=> $"{ExportingModuleName.RemoveDllExtension()}.{ExportedFunctionName}";
}
