using InjectDotnet.Native;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace InjectDotnet;

#pragma warning disable CS9191 // The 'ref' modifier for an argument corresponding to 'in' parameter is equivalent to 'in'. Consider using 'in' instead.
public static class ProcessExtensions
{
	private const string LOADLIBRARY = "LoadLibraryW";
	private static readonly nint LoadLibrary_Offset;


	static ProcessExtensions()
	{
		if (GetExportOffset(NativeMethods.Kernel32LibraryName, LOADLIBRARY) is not nint offset)
			throw new DllNotFoundException();
		LoadLibrary_Offset = offset;
	}

	public static bool? Is64bit(this Process proc)
	{
		try
		{
			return
				Environment.Is64BitOperatingSystem
				&& NativeMethods.IsWow64Process(proc.SafeHandle, out var is32)
				&& !is32;
		}
		catch
		{
			return null;
		}
	}

	public static string? GetHostFxrLib(this Process process)
		=> process.GetModulesByName("hostfxr.dll").FirstOrDefault()?.FileName;

	public static bool HasReadAccess(this MemoryProtection protection)
		=> protection is
		MemoryProtection.ReadOnly or
		MemoryProtection.ReadWrite or
		MemoryProtection.ExecuteRead or
		MemoryProtection.ExecuteReadWrite or
		MemoryProtection.ExecuteWriteCopy or
		MemoryProtection.WriteCopy or
		MemoryProtection.WriteCombine;

	public static bool HasWriteAccess(this MemoryProtection protection)
		=> protection is
		MemoryProtection.ReadWrite or
		MemoryProtection.WriteCombine or
		MemoryProtection.ExecuteReadWrite;

	public static bool HasExecuteAccess(this MemoryProtection protection)
		=> protection is
		MemoryProtection.Execute or
		MemoryProtection.ExecuteRead or
		MemoryProtection.ExecuteReadWrite or
		MemoryProtection.ExecuteWriteCopy;


	public static IEnumerable<ProcessModule> GetModulesByName(this Process proc, string name)
	{
		proc.Refresh();

		return
			proc.Modules
			.Cast<ProcessModule>()
			.Where(m =>
				m.ModuleName?.Equals(name, StringComparison.OrdinalIgnoreCase) is true ||
				m.FileName?.Equals(name, StringComparison.OrdinalIgnoreCase) is true);
	}

	public static ProcessModule GetKernel32(this Process proc)
	{
		return proc.GetModulesByName(NativeMethods.Kernel32LibraryName).Single();
	}

	public static ProcessModule? LoadLibrary(this Process proc, string dll)
	{
		proc.Call(proc.GetKernel32().BaseAddress + LoadLibrary_Offset, dll);

		return proc.GetModulesByName(dll).FirstOrDefault();
	}

	public static nint GetProcAddress(this ProcessModule mod, string procName)
	{
		var modName = mod.FileName ?? mod.ModuleName;
		if (modName is null || GetExportOffset(modName, procName) is not nint offset)
			throw new MissingMethodException($"Failed to get address of {modName}.{procName} in target process");

		return mod.BaseAddress + offset;
	}

	public static void Free(this Process proc, IntPtr handle)
		=> NativeMethods.VirtualFreeEx(proc.SafeHandle, handle, 0, AllocationType.Release);

	public static nint WriteMemory<T>(this Process hProcess, T argument) where T : struct
	{
		var size = Marshal.SizeOf<T>();
		Span<byte> buff = new byte[size];
		MemoryMarshal.Write(buff, ref argument);
		return hProcess.WriteMemory(buff);
	}

	public static nint WriteMemory(this Process proc, string argument)
		=> proc.WriteMemory(MemoryMarshal.AsBytes(argument.AsSpan()));

	public static unsafe nint WriteMemory(this Process hProcess, ReadOnlySpan<byte> buffer, MemoryProtection protection = MemoryProtection.ReadWrite)
	{
		IntPtr baseAddress = NativeMethods.VirtualAllocEx(hProcess.Handle, IntPtr.Zero, buffer.Length, AllocationType.ReserveCommit, protection);

		fixed (byte* b = buffer)
			NativeMethods.WriteProcessMemory(hProcess.Handle, baseAddress, b, buffer.Length, out var numBytesWritten);

		return baseAddress;
	}

	public static int? Call<T>(this Process proc, IntPtr function, T argument, bool waitForExit = true) where T : struct
	{
		var arg = proc.WriteMemory(argument);
		return proc.Call(function, arg, waitForExit);
	}

	public static int? Call(this Process proc, IntPtr function, string argument, bool waitForExit = true)
	{
		var arg = proc.WriteMemory(argument);
		return proc.Call(function, arg, waitForExit);
	}

	public static int? Call(this Process proc, IntPtr function, ReadOnlySpan<byte> argument, bool waitForExit = true)
	{
		var arg = proc.WriteMemory(argument);
		return proc.Call(function, arg, waitForExit);
	}

	public static int? Call(this Process proc, IntPtr function, IntPtr argument, bool waitForExit = true)
	{
		IntPtr hThread = NativeMethods.CreateRemoteThread(proc.SafeHandle, IntPtr.Zero, 0, function, argument, 0, out _);

		try
		{
			if (!waitForExit) return null;

			NativeMethods.WaitForSingleObject(hThread, -1);

			proc.Free(argument);

			bool isSucceeded = NativeMethods.GetExitCodeThread(hThread, out int exitCode);

			return isSucceeded ? exitCode : null;
		}
		catch
		{
			proc.Free(argument);
			throw;
		}
		finally
		{
			NativeMethods.CloseHandle(hThread);
		}
	}

	public static nint? GetExportOffset(string library, string functionName)
	{
		if (!NativeLibrary.TryLoad(library, out nint hModule))
			return null;

		try
		{
			if (!NativeLibrary.TryGetExport(hModule, functionName, out nint hExport))
				return null;

			return hExport - hModule;
		}
		finally
		{
			NativeLibrary.Free(hModule);
		}
	}
}
