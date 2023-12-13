using System.Diagnostics;

namespace InjectDotnet.NativeHelper
{
	/// <summary>
	/// A record of a function exported by a native module.
	/// </summary>
	[DebuggerDisplay("{ToString(),nq}")]
	public class NativeExport
	{
		/// <summary>The module exporting the function</summary>
		public ProcessModule Module { get; }
		/// <summary>Relative virtual address of the function's entry in <see cref="Module"/>'s Export Address Table</summary>
		public uint EAT_RVA { get; }
		/// <summary>The function's export ordinal</summary>
		public ushort Ordinal { get; }
		/// <summary>The address of the exported symbol when loaded into memory.</summary>
		public uint? FunctionRVA { get; }
		/// <summary>The name of the module and function to which this export forwards</summary>
		public
#if NULLABLE
		string?
#else
		string
#endif
			Forwarded { get; }
		/// <summary>The name of the exported function</summary>
		public
#if NULLABLE
		string?
#else
		string
#endif
			FunctionName
		{ get; internal set; }

		internal NativeExport(ProcessModule module, uint eat_RVA, ushort ordinal, uint? functionRVA,
#if NULLABLE
		string?
#else
		string
#endif
			forwarded)
		{
			Module = module;
			EAT_RVA = eat_RVA;
			Ordinal = ordinal;
			FunctionRVA = functionRVA;
			Forwarded = forwarded;
		}

		public override string ToString()
		{
			var modName = Module.ModuleName?.RemoveDllExtension() ?? "[Module]";

			if (FunctionName == null)
			{
				return $"{modName}.@{Ordinal}";
			}
			else
			{
				if (Forwarded == null)
				{
					return $"{modName}.{FunctionName}";
				}
				else
				{
					return $"{modName}.{FunctionName} -> {Forwarded}";
				}
			}
		}
	}
}