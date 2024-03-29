﻿using InjectDotnet.NativeHelper.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace InjectDotnet.NativeHelper
{
	unsafe public static class NativeExtensions
	{
		/// <summary>
		/// Hook a native dll import with an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
		/// </summary>
		/// <param name="import">The import to hook</param>
		/// <param name="hook">A pointer to an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
		/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
		/// with the same parameter signature as the native import</param>
		/// <returns>A valid <see cref="ImportHook"/> if successful</returns>
		public static
#if NULLABLE
			ImportHook?
#else
			ImportHook
#endif

			Hook(this
#if NULLABLE
			NativeImport?
#else
			NativeImport
#endif
			import, void* hook, bool installAfterCreate = true)
		{
			var hookPointer = (IntPtr)hook;
			if (import == null || hookPointer == IntPtr.Zero) return null;
			return ImportHook.Create(import, hookPointer, installAfterCreate);
		}

		/// <summary>
		/// Hook a native dll import with a managed <see cref="Delegate"/>
		/// </summary>
		/// <param name="import">The import to hook</param>
		/// <param name="hook">A managed delegate with the same parameter signature as the native import</param>
		/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
		/// <returns>A valid <see cref="ImportHook"/> if successful</returns>
		public static
#if NULLABLE
			ImportHook?
#else
			ImportHook
# endif
			Hook<TDelegate>(this
#if NULLABLE
			NativeImport?
#else
			NativeImport
#endif
			 import, TDelegate hook, bool installAfterCreate = true)
			where TDelegate : Delegate
		{
			var hookPointer = Marshal.GetFunctionPointerForDelegate(hook);
			if (import == null || hookPointer == IntPtr.Zero) return null;
			return ImportHook.Create(import, hookPointer, installAfterCreate);
		}

		/// <summary>
		/// Hook a native dll export function on a single thread with a
		/// <see cref="Delegate"/> using hardware breakpoints.
		/// </summary>
		/// <param name="export">The export to hook</param>
		/// <param name="hook">A managed delegate with the same parameter signature as the native export</param>
		/// <param name="thread">The process thread on which the hook is activated. Usually themain thread,
		/// which can be guessed at by choosing the oldest <see cref="ProcessThread.StartTime"/></param>
		/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
		/// <remarks>
		/// NOTE: <see cref="BreakpointHook"/> cannot be debugged. The debugger will hang on the breakpoint and deadlock.
		/// </remarks>
		/// <returns>A valid <see cref="BreakpointHook"/> if successful</returns>
		public static
#if NULLABLE
			BreakpointHook?
#else
			BreakpointHook
#endif

			Hook<TDelegate>(this
#if NULLABLE
			NativeExport?
#else
			NativeExport
#endif
			export, TDelegate hook,
#if NULLABLE
			ProcessThread?
#else
			ProcessThread
#endif
			thread, bool installAfterCreate = true)
			where TDelegate : Delegate
		{
			var hookPointer = Marshal.GetFunctionPointerForDelegate(hook);
			if (export == null ||
				hookPointer == IntPtr.Zero ||
				thread == null ||
				!export.FunctionRVA.HasValue) return null;

			return BreakpointHook.Create(export.Module.BaseAddress.Add((IntPtr)export.FunctionRVA.Value), hookPointer, thread.Id, installAfterCreate);
		}

		/// <summary>
		/// Hook a native dll export with an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
		/// </summary>
		/// <param name="export">The export to hook</param>
		/// <param name="hook">A pointer to an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
		/// with the same parameter signature as the native export</param>
		/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
		/// <returns>A valid <see cref="JumpHook"/> if successful</returns>
		public static
#if NULLABLE
			JumpHook?
#else
			JumpHook
#endif
			Hook(this
#if NULLABLE
			NativeExport?
#else
			NativeExport
#endif
			export, void* hook, bool installAfterCreate = true)
		{
			var hookPointer = (IntPtr)hook;
			if (export == null || hookPointer == IntPtr.Zero) return null;
			return JumpHook.Create(export, hookPointer, installAfterCreate);
		}

		/// <summary>
		/// Hook a native dll export function on a single thread with an
		/// <see cref="UnmanagedCallersOnlyAttribute"/> delegate using
		/// hardware breakpoints.
		/// </summary>
		/// <param name="export">The export to hook</param>
		/// <param name="hook">A pointer to an <see cref="UnmanagedCallersOnlyAttribute"/> delegate
		/// with the same parameter signature as the native export</param>
		/// <param name="thread">The process thread on which the hook is activated. Usually themain thread,
		/// which can be guessed at by choosing the oldest <see cref="ProcessThread.StartTime"/></param>
		/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
		/// <remarks>
		/// NOTE: <see cref="BreakpointHook"/> cannot be debugged. The debugger will hang on the breakpoint and deadlock.
		/// </remarks>
		/// <returns>A valid <see cref="BreakpointHook"/> if successful</returns>
		public static
#if NULLABLE
			BreakpointHook?
#else
			BreakpointHook
#endif
			Hook(this
#if NULLABLE
			NativeExport?
#else
			NativeExport
#endif
			export, void* hook,
#if NULLABLE
			ProcessThread?
#else
			ProcessThread
#endif
			thread, bool installAfterCreate = true)
		{
			var hookPointer = (IntPtr)hook;
			if (export == null ||
				hookPointer == IntPtr.Zero ||
				thread == null ||
				!export.FunctionRVA.HasValue) return null;
			return BreakpointHook.Create(export.Module.BaseAddress.Add((IntPtr)export.FunctionRVA.Value), hookPointer, thread.Id, installAfterCreate);
		}

		/// <summary>
		/// Hook a native dll export with a managed <see cref="Delegate"/>
		/// </summary>
		/// <param name="export">The export to hook</param>
		/// <param name="hook">A managed delegate with the same parameter signature as the native export</param>
		/// <param name="installAfterCreate">If true hook creation only succeeds if <see cref="INativeHook.InstallHook"/> returns true</param>
		/// <returns>A valid <see cref="JumpHook"/> if successful</returns>
		public static
#if NULLABLE
			JumpHook?
#else
			JumpHook
#endif
			Hook<TDelegate>(this
#if NULLABLE
			NativeExport?
#else
			NativeExport
#endif
			export, TDelegate hook, bool installAfterCreate = true)
			where TDelegate : Delegate
		{
			var hookPointer = Marshal.GetFunctionPointerForDelegate(hook);
			if (export == null || hookPointer == IntPtr.Zero) return null;
			return JumpHook.Create(export, hookPointer, installAfterCreate);
		}

		/// <summary>
		/// Get a function exported by a <see cref="ProcessModule"/>
		/// </summary>
		/// <param name="procModule">The module which exports <paramref name="exportedFunctionName"/></param>
		/// <param name="exportedFunctionName">Name of the exported function</param>
		/// <returns>The matched <see cref="NativeExport"/></returns>
		public static
#if NULLABLE
			NativeExport?
#else
			NativeExport
#endif
			GetExportByName(this
#if NULLABLE
			ProcessModule?
#else
			ProcessModule
#endif
			procModule, string exportedFunctionName)
			=> procModule?.GetModuleExports()?.SingleOrDefault(e => e.FunctionName == exportedFunctionName);

		/// <summary>
		/// Get a function imported by a <see cref="ProcessModule"/>
		/// </summary>
		/// <param name="procModule">The module which imports the function</param>
		/// <param name="libraryName">Name of the imported library</param>
		/// <param name="importedFunctionName">Name of the function imported from <paramref name="libraryName"/></param>
		/// <returns>The matched <see cref="NativeImport"/></returns>
		public static
#if NULLABLE
			NativeImport?
#else
			NativeImport
#endif
			GetImportByName(this
#if NULLABLE
			ProcessModule?
#else
			ProcessModule
#endif
			procModule, string libraryName, string importedFunctionName)
		{
			var imports = procModule?.GetModuleImports();
			if (imports == null) return null;

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
		/// Get <see cref="ProcessModule"/>s by <see cref="ProcessModule.ModuleName"/> or <see cref="ProcessModule.FileName"/>
		/// </summary>
		/// <param name="proc">The process whose modules are searched for matches</param>
		/// <param name="pattern"><see cref="Regex"/> pattern to match to the ModuleName or FileName of the module</param>
		/// <returns>All modules with matching names</returns>
		public static IEnumerable<ProcessModule> GetModulesByName(this Process proc, Regex pattern)
		{
			proc.Refresh();
			return proc.Modules
				.Cast<ProcessModule>()
				.Where(m =>
					m.ModuleName != null && pattern.IsMatch(m.ModuleName) is true ||
					m.FileName != null && pattern.IsMatch(m.FileName) is true);
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
		public static
#if NULLABLE
			List<NativeImport>?
#else
			List<NativeImport>
#endif
			GetModuleImports(this
#if NULLABLE
			ProcessModule?
#else
			ProcessModule
#endif
			procModule)
		{
			if (procModule?.FileName == null) return null;

			ReadDirectoriesAndSections(procModule, out var imageDataDirs, out var imageSections);
			var importDataDir = imageDataDirs[1]; //Import directory is always index 1

			if (importDataDir.Size == 0) return null; //Module has no imports

			using (var peFile = new BinaryReader(File.Open(procModule.FileName, FileMode.Open, FileAccess.Read, FileShare.Read)))
			{

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
					while (*(IntPtr*)(hModule + iatEntryRVA) != IntPtr.Zero)
					{
						//Read the IAT entry from the PE file
						peFile.BaseStream.Position =
							iatEntryRVA - importSection.VirtualAddress + importSection.PointerToRawData;
#if X64
						long entry = peFile.ReadInt64();
#elif X86
						long entry = peFile.ReadInt32();
#endif

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
							((i.FunctionName != null && i.FunctionName == import.FunctionName) ||
							(i.Ordinal != null && i.Ordinal == import.Ordinal))) is NativeImport existing)
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
						iatEntryRVA += (uint)IntPtr.Size;
					}
				}
				return list;
			}
		}

		/// <summary>
		/// Get all functions exported by a <see cref="ProcessModule"/>
		/// </summary>
		/// <param name="procModule">The <see cref="ProcessModule"/> from which imports are read</param>
		/// <returns>If successful, a list of all functions exported by <paramref name="procModule"/></returns>
		public static
#if NULLABLE
			List<NativeExport>?
#else
			List<NativeExport>
#endif
			GetModuleExports(this
#if NULLABLE
			ProcessModule?
#else
			ProcessModule
#endif
			procModule)
		{
			if (procModule?.FileName == null) return null;

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
				var eat_rva = (uint)((IntPtr)pExport).Subtract(procModule.BaseAddress);
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

			return exports.Where(e => e != null).ToList();
		}

		internal static bool EqualsIgnoreCase(this string str, string other)
			=> str.Equals(other, StringComparison.OrdinalIgnoreCase);

		internal static string RemoveDllExtension(this string libName)
			=> libName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? libName.Remove(libName.Length - 4, 4) : libName;

		private static string NullTerminatedUtf8(byte* pStr)
		{
			int count = 0;
			while(*(pStr + count) != 0)
				count++;

			return Encoding.UTF8.GetString(pStr, count);
		}

		/// <summary>
		/// Loads PE information for a module in the executing process
		/// </summary>
		/// <param name="module">A <see cref="ProcessModule"/> in the executing process</param>
		/// <param name="dataDirectories">All image data directories</param>
		/// <param name="secHeaders">All image section headers</param>
		private static void ReadDirectoriesAndSections(
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
			var pStructs = hModule + lfanew +

#if X64
			0x84;
#elif X86
			0x74;
#endif
			var numRvaAndSizes = *(int*)pStructs;

			pStructs += sizeof(int);
			dataDirectories = new Span<ImageDataDirectory>(pStructs, numRvaAndSizes).ToArray();

			pStructs += sizeof(ImageDataDirectory) * numRvaAndSizes;
			secHeaders = new Span<ImageSectionHeader>(pStructs, NumberOfSections).ToArray();
		}
	}
}