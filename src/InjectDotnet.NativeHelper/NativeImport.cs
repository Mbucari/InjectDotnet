using System.Collections.ObjectModel;
using System.Diagnostics;

namespace InjectDotnet.NativeHelper
{
	/// <summary>
	/// A record of an external function imported by a native module.
	/// </summary>
	[DebuggerDisplay("{ToString(),nq}")]
	public class NativeImport
	{
		/// <summary>The module importing the function</summary>
		public ProcessModule Module { get; }
		/// <summary>The name of the external library containing the imported function</summary>
		public string Library { get; }
		/// <summary>The function's ordinal</summary>
		public ushort? Ordinal { get; internal set; }
		/// <summary>The name of the function exported by <see cref="Library"/> which is imported by <see cref="Module"/></summary>
		public
#if NULLABLE
			string?
#else
			string
#endif
			FunctionName { get; internal set; }
		/// <summary>Relative virtual address of the function's entries in <see cref="Module"/>'s Import Address Table
		/// <br/><br/>
		/// It's possible that the same function appears more than once in the import table, so
		/// IAT RVAs of all occurrences of the same imported function are included.
		/// </summary>
		public ReadOnlyCollection<uint> IAT_RVAs { get; internal set; }

		internal NativeImport(ProcessModule module, string library, ushort? ordinal,
#if NULLABLE
			string?
#else
			string
# endif
			functionName, uint iat_RVA)
		{
			Module = module;
			Library = library;
			Ordinal = ordinal;
			FunctionName = functionName;
			IAT_RVAs = new ReadOnlyCollection<uint>(new uint[] { iat_RVA });
		}

		public override string ToString()
		{
			var modName = Module.ModuleName?.RemoveDllExtension() ?? "[Module]";
			if (FunctionName != null)
			{
				return $"{modName}<{Library}.{FunctionName}>";
			}
			else if (Ordinal != null)
			{
				return $"{modName}<{Library}.@{Ordinal}>";
			}
			else
			{
				return $"{modName}<{Library}.[NULL]>";
			}
		}
	}
}