﻿using InjectDotnet.NativeHelper.Native;
using System;
using System.Diagnostics;
using System.Linq;

#if !NET
using nint = System.IntPtr;
#endif

namespace InjectDotnet.NativeHelper
{
	/// <summary>An instance of a hooked <see cref="NativeImport"/></summary>
	[DebuggerDisplay("{DebuggerDisplay,nq}")]
	public class ImportHook : INativeHook
	{
		private bool isHooked;
		/// <summary>The <see cref="ProcessModule"/> whose import address table is modified to hook
		/// calls to <see cref="OriginalFunction"/> in <see cref="ImportedModuleName"/></summary>
		public ProcessModule HookedModule { get; }
		/// <summary>Name of the module containing the <see cref="OriginalFunction"/> that's being hooked</summary>
		public string ImportedModuleName { get; }
		/// <summary>Name of the imported function that's being hooked</summary>
		public string ImportedFunctionName { get; }
		/// <summary>Entry point of <see cref="ImportedFunctionName"/></summary>
		public nint OriginalFunction { get; }
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

		/// <summary>Address of the delegate that is hooking <see cref="OriginalFunction"/></summary>
		public nint HookFunction { get; }
		/// <summary>
		/// Locations in <see cref="HookedModule"/>'s IAT that points to <see cref="OriginalFunction"/>
		/// </summary>
		private nint[] IATEntries { get; }

		private unsafe ImportHook(
			ProcessModule hookedModule,
			string importingModuleName,
			string importedFunctionName,
			nint hookFunction,
			nint[] iatEntries)
		{
			HookedModule = hookedModule;
			ImportedModuleName = importingModuleName;
			ImportedFunctionName = importedFunctionName;
			HookFunction = hookFunction;
			IATEntries = iatEntries;

			//Store the location of the original function. It will be
			//the same regardless of how many times it's imported.
			var pImportTableEntry = (nint*)IATEntries[0];
			OriginalFunction = *pImportTableEntry;
		}

		unsafe public bool InstallHook()
		{
			if (IsDisposed)
				throw new ObjectDisposedException(nameof(JumpHook));

			lock (this)
			{
				if (IsHooked) return false;

				var didReplace = false;
				foreach (nint* pImportTableEntry in IATEntries)
				{
					MemoryProtection oldProtect;
					NativeMethods.VirtualProtect((nint)pImportTableEntry, (nint)sizeof(nint), MemoryProtection.ReadWrite, &oldProtect);
					//Replace the original function pointer in the IAT with the hook pointer;
					*pImportTableEntry = HookFunction;
					//Restore IAT's protection
					NativeMethods.VirtualProtect((nint)pImportTableEntry, (nint)sizeof(nint), oldProtect, &oldProtect);
					didReplace = true;
				}

				return isHooked = didReplace && OriginalFunction != IntPtr.Zero;
			}
		}

		unsafe public bool RemoveHook()
		{
			if (IsDisposed)
				throw new ObjectDisposedException(nameof(JumpHook));

			lock (this)
			{
				if (!IsHooked) return false;

				var didReplace = false;
				foreach (nint* pImportTableEntry in IATEntries)
				{
					MemoryProtection oldProtect;
					NativeMethods.VirtualProtect((nint)pImportTableEntry, (nint)sizeof(ulong), MemoryProtection.ExecuteReadWrite, &oldProtect);
					*pImportTableEntry = OriginalFunction;
					//Restore IAT's protection
					NativeMethods.VirtualProtect((nint)pImportTableEntry, (nint)sizeof(ulong), oldProtect, &oldProtect);
					didReplace = true;
				}

				return !(isHooked = !didReplace);
			}
		}

		/// <summary>
		/// Create an <see cref="ImportHook"/> for a native function imported by a native library in this process.
		/// </summary>
		/// <param name="import">The imported function to be hooked.</param>
		/// <param name="hookFunction">Address of a delegate that will be called instead of <see cref="NativeImport.FunctionName"/></param>
		/// <returns>A valid <see cref="ImportHook"/> if successful</returns>
#if NULLABLE
		public static ImportHook? Create(
#else
		public static ImportHook Create(
#endif
			NativeImport import,
			nint hookFunction,
			bool installAfterCreate = true)
		{
			if (hookFunction == IntPtr.Zero || import.IAT_RVAs.Count is 0) return null;

			var funcName = import.Ordinal is ushort ordinal ? $"@{ordinal}" : import.FunctionName;
			if (funcName == null) return null;

			var iatEntries
				= import.IAT_RVAs
				.Select(r => import.Module.BaseAddress.Add((nint)r))
				.ToArray();

			var hook = new ImportHook(import.Module, import.Library, funcName, hookFunction, iatEntries);

			return !installAfterCreate || hook.InstallHook() ? hook : null;
		}

		[DebuggerBrowsable(DebuggerBrowsableState.Never)]
		private string DebuggerDisplay => $"{ToString()}, {nameof(IsHooked)} = {IsHooked}";
		public override string ToString()
			=> $"{HookedModule.ModuleName ?? HookedModule.FileName ?? "[MODULE]"}<{ImportedModuleName.RemoveDllExtension()}.{ImportedFunctionName}>";

		public void Dispose()
		{
			if (!IsDisposed)
			{
				RemoveHook();
				IsDisposed = true;
			}
		}
	}
}