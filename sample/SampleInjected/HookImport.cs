using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SampleInjected
{
	public record Import(string Library, ushort? Hint, string? Function, short? Ordinal, uint IAT_RVA);

	unsafe internal static class HookImport
	{
		/// <summary>
		/// Replace an imported function with a delegate
		/// </summary>
		/// <param name="moduleName">Name of the imported library containing the function to hook</param>
		/// <param name="functionName">Name of the function to hook</param>
		/// <param name="hookFunction">Pointer to a manager delegate that will be called instead of <paramref name="functionName"/></param>
		/// <param name="originalFunction">Pointer to the function being hooked</param>
		/// <returns>Success</returns>
		public static bool InstallHook(
			string moduleName,
			string functionName,
			nint hookFunction,
			nint* originalFunction)
		{
			var mainModule = Process.GetCurrentProcess().MainModule;

			if (mainModule is null ||
				GetImports(mainModule) is not List<Import> imports ||
				imports.Count == 0) return false;

			var toReplace = imports.Where(i =>
				i.Library.Equals(moduleName, StringComparison.OrdinalIgnoreCase) &&
				i.Function?.Equals(functionName, StringComparison.OrdinalIgnoreCase) is true).ToList();

			var didReplace = false;

			//It's possible that the same function appears more than once in the import table.
			//Replace all occurances with the hook, but only keep one copy of the original
			//(because they're the same function so the function's addresses will be the same)
			foreach (var r in toReplace)
			{
				var pImportTableEntry = (nint*)(mainModule.BaseAddress + (int)r.IAT_RVA);

				*originalFunction = *pImportTableEntry;

				uint oldProtect;
				//Change IAT protection to read-write
				VirtualProtect((nint)pImportTableEntry, sizeof(nint), 4u, &oldProtect);
				//Replace the original function pointer in the IAT with the hook pointer;
				*pImportTableEntry = hookFunction;
				//Restore IAT's protection
				VirtualProtect((nint)pImportTableEntry, sizeof(nint), oldProtect, &oldProtect);
				didReplace = true;
			}
			return didReplace;
		}

		/// <summary>
		/// Geta all imported functions from the main executable of this process.
		/// </summary>
		/// <param name="mainModule"><see cref="Process.MainModule"/></param>
		/// <remarks>
		/// When the PE is loaded, FirstThunk (aka Import Address Table) is overwritten with
		/// the addresses of the symbols that are being imported, which is why import name RVAs
		/// must be read from the PE file and not from memory. Name RVAs could be located in
		/// memory by using OriginalFirstThunk (aka Import Lookup Table) (which is idential to
		/// FirstThunk but is not overwritten when the PE is loaded); however, not all PE files
		/// Contain an Import Lookup Table. The only way to guarantee that imported function
		/// names can be resolved is by reading from the PE file's Import Address Table.
		/// </remarks>
		/// <returns>If successful, a list of all imported functions</returns>
		public static List<Import>? GetImports(ProcessModule? mainModule)
		{
			if (mainModule?.FileName is null) return null;

			using var peFile = new BinaryReader(File.OpenRead(mainModule.FileName));

			var list = new List<Import>();
			byte* hModule = (byte*)mainModule.BaseAddress;

			ReadDirectoriesAndSections(mainModule.BaseAddress, out var dir, out var secs);
			var importDir = dir[1]; //Import directory is always index 1

			var importDescriptors =
				new Span<ImageImportDescriptor>(
					hModule + importDir.RVA,
					(int)importDir.Size / sizeof(ImageImportDescriptor));

			foreach (var imgImpDes in importDescriptors)
			{
				if (imgImpDes.FirstThunk == 0) break;

				//Name of the dll being imported
				var libName =
					Encoding.UTF8.GetString(
						MemoryMarshal
						.CreateReadOnlySpanFromNullTerminated(hModule + imgImpDes.Name));

				//PE section containing the IAT for this import descriptor.
				//The import directory is contiguous and must be inside a single section.
				//Each import's Import Address Table is contiguous and must be inside a single section.
				//However, each import may store its IAT in a different section.
				var importSection =
					secs.Single(s =>
						imgImpDes.FirstThunk >= s.VirtualAddress &&
						imgImpDes.FirstThunk < s.VirtualAddress + s.VirtualSize);

				//RVA of the first import address for this import descriptor
				var iatEntryRVA = imgImpDes.FirstThunk;

				while (*(nint*)(hModule + iatEntryRVA) != 0)
				{
					//Read the IAT entry from the PE file
					peFile.BaseStream.Position =
						iatEntryRVA + importSection.PointerToRawData - importSection.VirtualAddress;

					long entry = Environment.Is64BitProcess ? peFile.ReadInt64() : peFile.ReadInt32();

					Import import;
					if (entry < 0)
					{
						//The entry is an ordinal and has no name
						var ordinal = (short)(entry & short.MaxValue);

						import = new Import(libName, null, null, ordinal, iatEntryRVA);
					}
					else
					{
						var hint = *(ushort*)(hModule + (uint)entry);
						//The imported function's name is a null-terminated UTF-8 string
						var name =
							Encoding.UTF8.GetString(
								MemoryMarshal
								.CreateReadOnlySpanFromNullTerminated(hModule + (uint)entry + sizeof(ushort)));

						import = new Import(libName, hint, name, null, iatEntryRVA);
					}
					list.Add(import);
					//Move to the next entry in the table
					iatEntryRVA += (uint)sizeof(nint);
				}
			}
			return list;
		}

		/// <summary>
		/// Loads PE imformation for the executing program
		/// </summary>
		/// <param name="baseAddress"><see cref="Process.MainModule"/> base address</param>
		/// <param name="dataDirectories">All image data directories</param>
		/// <param name="secHeaders">All image section headers</param>
		private unsafe static void ReadDirectoriesAndSections(
			nint baseAddress,
			out ImageDataDirectory[] dataDirectories,
			out ImageSectionHeader[] secHeaders)
		{
			byte* hModule = (byte*)baseAddress;

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

		[DllImport("kernel32.dll")]
		private static extern bool VirtualProtect(IntPtr handle, int size, uint newProtect, uint* oldProtect);

#pragma warning disable CS0649 // Field is never assigned to, and will always have its default value
		private struct ImageImportDescriptor
		{
			public uint OriginalFirstThunk;
			public uint TimeDateStamp;
			public uint ForwarderChain;
			public uint Name;
			public uint FirstThunk;
		}

		private struct ImageDataDirectory
		{
			public uint RVA;
			public uint Size;
		}

		private struct ImageSectionHeader
		{
			ulong _Name;
			public uint VirtualSize;
			public uint VirtualAddress;
			public uint SizeOfRawData;
			public uint PointerToRawData;
			public uint PointerToRelocations;
			public uint PointerToLinenumbers;
			public ushort NumberOfRelocations;
			public ushort NumberOfLinenumbers;
			public uint Characteristics;

			public string Name
			{
				get
				{
					var nameBts = BitConverter.GetBytes(_Name);
					int len = 8;
					for (; len > 0; len--)
					{
						if (nameBts[len - 1] != 0) break;
					}

					return Encoding.UTF8.GetString(nameBts, 0, len);
				}
			}
			public override string ToString() => Name;
		}
#pragma warning restore CS0649

	}
}
