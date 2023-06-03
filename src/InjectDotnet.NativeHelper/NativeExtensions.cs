using InjectDotnet.NativeHelper.Native;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace InjectDotnet.NativeHelper;

unsafe public static class NativeExtensions
{
	/// <summary>
	/// Hook a native dll import with an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
	/// </summary>
	/// <param name="import">The import to hook</param>
	/// <param name="hook">A pointer to an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
	/// with the same parameter signature as the native import</param>
	/// <returns>A valid <see cref="ImportHook"/> if successful</returns>
	public static ImportHook? Hook(this NativeImport? import, void* hook)
	{
		var hookPointer = (nint)hook;
		if (import is null || hookPointer == 0) return null;
		return ImportHook.Create(import, hookPointer);
	}

	/// <summary>
	/// Hook a native dll import with a managed <see cref="Delegate"/>
	/// </summary>
	/// <param name="import">The import to hook</param>
	/// <param name="hook">A managed delegate with the same parameter signature as the native import</param>
	/// <returns>A valid <see cref="ImportHook"/> if successful</returns>
	public static ImportHook? Hook<TDelegate>(this NativeImport? import, TDelegate hook) where TDelegate : Delegate
	{
		nint hookPointer = Marshal.GetFunctionPointerForDelegate(hook);
		if (import is null || hookPointer == 0) return null;
		return ImportHook.Create(import, hookPointer);
	}

	/// <summary>
	/// Hook a native dll export with an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
	/// </summary>
	/// <param name="export">The export to hook</param>
	/// <param name="hook">A pointer to an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
	/// with the same parameter signature as the native export</param>
	/// <remarks>
	/// While imports can be hooked by changing the function pointer in the module's IAT, exports can't be hooked so simply.
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
	public static ExportHook? Hook(this NativeExport? export, void* hook)
	{
		var hookPointer = (nint)hook;
		if (export is null || hookPointer == 0) return null;
		return ExportHook.Create(export, hookPointer);
	}

	/// <summary>
	/// Hook a native dll export with a managed <see cref="Delegate"/>
	/// </summary>
	/// <param name="export">The export to hook</param>
	/// <param name="hook">A managed delegate with the same parameter signature as the native export</param>
	/// <remarks>
	/// While imports can be hooked by changing the function pointer in the module's IAT, exports can't be hooked so simply.
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
	public static ExportHook? Hook<TDelegate>(this NativeExport? export, TDelegate hook) where TDelegate : Delegate
	{
		nint hookPointer = Marshal.GetFunctionPointerForDelegate(hook);
		if (export is null || hookPointer == 0) return null;
		return ExportHook.Create(export, hookPointer);
	}

	/// <summary>
	/// Get a function exported by a <see cref="ProcessModule"/>
	/// </summary>
	/// <param name="procModule">The module which exports <paramref name="exportedFunctionName"/></param>
	/// <param name="exportedFunctionName">Name of the exported function</param>
	/// <returns>The matched <see cref="NativeExport"/></returns>
	public static NativeExport? GetExportByName(this ProcessModule? procModule, string exportedFunctionName)
		=> procModule?.GetModuleExports()?.SingleOrDefault(e => e.FunctionName == exportedFunctionName);

	/// <summary>
	/// Get a function imported by a <see cref="ProcessModule"/>
	/// </summary>
	/// <param name="procModule">The module which imports the function</param>
	/// <param name="libraryName">Name of the imported library</param>
	/// <param name="importedFunctionName">Name of the function imported from <paramref name="libraryName"/></param>
	/// <returns>The matched <see cref="NativeImport"/></returns>
	public static NativeImport? GetImportByName(this ProcessModule? procModule, string libraryName, string importedFunctionName)
	{
		var imports = procModule?.GetModuleImports();
		if (imports is null) return null;

		libraryName = libraryName.RemoveDllExtension();

		return
			imports
			.SingleOrDefault(i =>
				i.Module.BaseAddress == procModule?.BaseAddress &&
				i.Library.RemoveDllExtension().EqualsIgnoreCase(libraryName) &&
				i.FunctionName == importedFunctionName);
	}

	/// <summary>
	/// Get <see cref="ProcessModule"/>s by <see cref="ProcessModule.ModuleName"/> or <see cref="ProcessModule.FileName"/>
	/// </summary>
	/// <param name="proc">The process whose modules are searched for matches</param>
	/// <param name="libraryName">The ModuleName or FileName of the module. Case insensitive and file extension is ignored.</param>
	/// <returns>All modules with matching names</returns>
	public static IEnumerable<ProcessModule> GetModulesByName(this Process proc, string libraryName)
	{
		libraryName = libraryName.RemoveDllExtension();

		proc.Refresh();
		return proc.Modules
			.Cast<ProcessModule>()
			.Where(m =>
				m.ModuleName?.RemoveDllExtension().EqualsIgnoreCase(libraryName) is true ||
				m.FileName?.RemoveDllExtension().EqualsIgnoreCase(libraryName) is true);
	}

	/// <summary>
	/// Geta all functions imported by a <see cref="ProcessModule"/>
	/// </summary>
	/// <param name="procModule">The <see cref="ProcessModule"/> from which imports are read</param>
	/// <remarks>
	/// When the PE is loaded, FirstThunk (aka Import Address Table) is overwritten with
	/// the addresses of the symbols that are being imported, which is why import libraryName RVAs
	/// must be read from the PE file and not from memory. FunctionName RVAs could be located in
	/// memory by using OriginalFirstThunk (aka Import Lookup Table) (which is identical to
	/// FirstThunk but is not overwritten when the PE is loaded); however, not all PE files
	/// Contain an Import Lookup Table. The only way to guarantee that imported function
	/// names can be resolved is by reading from the PE file's Import Address Table.
	/// </remarks>
	/// <returns>If successful, a list of all functions imported by <paramref name="procModule"/></returns>
	public static List<NativeImport>? GetModuleImports(this ProcessModule? procModule)
	{
		if (procModule?.FileName is null) return null;

		ReadDirectoriesAndSections(procModule, out var imageDataDirs, out var imageSections);
		var importDataDir = imageDataDirs[1]; //Import directory is always index 1

		if (importDataDir.Size == 0) return null; //Module has no imports

		using var peFile = new BinaryReader(File.Open(procModule.FileName, FileMode.Open, FileAccess.Read, FileShare.Read));

		var list = new List<NativeImport>();
		byte* hModule = (byte*)procModule.BaseAddress;

		var importDescriptors =
			new Span<ImageImportDescriptor>(
				hModule + importDataDir.RVA,
				(int)importDataDir.Size / sizeof(ImageImportDescriptor));

		foreach (var imgImpDes in importDescriptors)
		{
			if (imgImpDes.FirstThunk == 0) break;

			//FunctionName of the dll being imported
			var libName = NullTerminatedUtf8(hModule + imgImpDes.Name);

			//PE section containing the IAT for this import descriptor.
			//The import directory is contiguous and must be inside a single section.
			//Each import's Import Address Table is contiguous and must be inside a single section.
			//However, the IATs for all imports are not guaranteed to be contiguous and may be stored in different sections.
			var importSection =
				imageSections.Single(s =>
					imgImpDes.FirstThunk >= s.VirtualAddress &&
					imgImpDes.FirstThunk < s.VirtualAddress + s.VirtualSize);

			//RVA of the first import address for this import descriptor
			var iatEntryRVA = imgImpDes.FirstThunk;

			//End of IAT is denoted by a null entry
			while (*(nint*)(hModule + iatEntryRVA) != 0)
			{
				//Read the IAT entry from the PE file
				peFile.BaseStream.Position =
					iatEntryRVA - importSection.VirtualAddress + importSection.PointerToRawData;

				long entry = Environment.Is64BitProcess ? peFile.ReadInt64() : peFile.ReadInt32();

				NativeImport import;
				if (entry < 0)
				{
					//The entry is an ordinal and has no libraryName
					var ordinal = (ushort)(entry & ushort.MaxValue);

					import = new NativeImport(procModule, libName, ordinal, null, iatEntryRVA);
				}
				else
				{
					var hint = *(ushort*)(hModule + (uint)entry);
					//The imported function's libraryName is a null-terminated UTF-8 string
					var name = NullTerminatedUtf8(hModule + (uint)entry + sizeof(ushort));

					import = new NativeImport(procModule, libName, null, name, iatEntryRVA);
				}

				if (list.FirstOrDefault(i
					=> i.Library == import.Library &&
					((i.FunctionName is not null && i.FunctionName == import.FunctionName) ||
					(i.Ordinal is not null && i.Ordinal == import.Ordinal))) is NativeImport existing)
				{
					//It's possible that the same function appears more than once in the import table.
					//Group all occurrences into a single NativeImport with multiple IAT RVAs

					var rvas = new List<uint>(existing.IAT_RVAs.Count + 1);
					rvas.AddRange(existing.IAT_RVAs);
					rvas.Add(import.IAT_RVAs[0]);
					existing.IAT_RVAs = rvas.AsReadOnly();
				}
				else
					list.Add(import);

				//Move to the next entry in the table
				iatEntryRVA += (uint)sizeof(nint);
			}
		}
		return list;
	}

	/// <summary>
	/// Get all functions exported by a <see cref="ProcessModule"/>
	/// </summary>
	/// <param name="procModule">The <see cref="ProcessModule"/> from which imports are read</param>
	/// <returns>If successful, a list of all functions exported by <paramref name="procModule"/></returns>
	public static List<NativeExport>? GetModuleExports(this ProcessModule? procModule)
	{
		if (procModule?.FileName is null) return null;

		ReadDirectoriesAndSections(procModule, out var imageDataDirs, out _);
		var exportDataDir = imageDataDirs[0]; //Export directory is always index 0

		if (exportDataDir.Size == 0) return null; //Module has no imports

		byte* hModule = (byte*)procModule.BaseAddress;

		var exportDirectory = *(ImageExportDirectory*)(hModule + exportDataDir.RVA);

		var exports = new NativeExport[exportDirectory.NumberOfFunctions];

		var pExport = (uint*)(hModule + exportDirectory.AddressOfFunctions);
		for (uint i = 0; i < exportDirectory.NumberOfFunctions; i++, pExport++)
		{
			var export = *pExport;
			var eat_rva = (uint)((nint)pExport - procModule.BaseAddress);
			var ordinal = (ushort)(exportDirectory.Base + i);
			if (export >= exportDataDir.RVA && export < exportDataDir.RVA + exportDataDir.Size)
			{
				//Forwarder
				var forwardedName = NullTerminatedUtf8(hModule + export);
				exports[i] = new NativeExport(procModule, eat_rva, ordinal, null, forwardedName);
			}
			else if (export != 0)
			{
				//Export
				exports[i] = new NativeExport(procModule, eat_rva, ordinal, export, null);
			}
		}

		//The export libraryName pointer table and the export ordinal table form two parallel arrays that
		//are separated to allow natural field alignment. These two tables, in effect, operate as
		//one table, in which the Export FunctionName Pointer column points to a public (exported) libraryName and
		//the Export Ordinal column gives the corresponding ordinal for that public libraryName.
		uint* pNameRva = (uint*)(hModule + exportDirectory.AddressOfNames);
		ushort* pNameOrdinal = (ushort*)(hModule + exportDirectory.AddressOfNameOrdinals);
		for (int i = 0; i < exportDirectory.NumberOfNames; i++, pNameRva++, pNameOrdinal++)
		{
			exports[*pNameOrdinal].FunctionName = NullTerminatedUtf8(hModule + *pNameRva);
		}

		return exports.Where(e => e is not null).ToList();
	}


	internal static bool EqualsIgnoreCase(this string str, string other)
		=> str.Equals(other, StringComparison.OrdinalIgnoreCase);

	internal static string RemoveDllExtension(this string libName)
		=> libName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? libName[..^4] : libName;

	private static string NullTerminatedUtf8(byte* pStr)
		=> Encoding.UTF8.GetString(
			MemoryMarshal
			.CreateReadOnlySpanFromNullTerminated(pStr));

	/// <summary>
	/// Loads PE information for a module in the executing process
	/// </summary>
	/// <param name="module">A <see cref="ProcessModule"/> in the executing process</param>
	/// <param name="dataDirectories">All image data directories</param>
	/// <param name="secHeaders">All image section headers</param>
	private unsafe static void ReadDirectoriesAndSections(
		ProcessModule module,
		out ImageDataDirectory[] dataDirectories,
		out ImageSectionHeader[] secHeaders)
	{
		byte* hModule = (byte*)module.BaseAddress;

		//Last field in IMAGE_DOS_HEADER
		var lfanew = *(int*)(hModule + 0x3c);

		//Skip PE\0\0 signature and IMAGE_FILE_HEADER.Machine
		var NumberOfSections = *(ushort*)(hModule + lfanew + 6);

		//Last field in IMAGE_OPTIONAL_HEADER
		var pStructs = hModule + lfanew + (Environment.Is64BitProcess ? 0x84 : 0x74);
		var numRvaAndSizes = *(int*)pStructs;

		pStructs += sizeof(int);
		dataDirectories = new Span<ImageDataDirectory>(pStructs, numRvaAndSizes).ToArray();

		pStructs += sizeof(ImageDataDirectory) * numRvaAndSizes;
		secHeaders = new Span<ImageSectionHeader>(pStructs, NumberOfSections).ToArray();
	}
}
