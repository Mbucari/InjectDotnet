using InjectDotnet.Native;
using System;
using System.Runtime.InteropServices;
using static InjectDotnet.Native.NativeMethods;


namespace InjectDotnet.Debug;

internal class MemoryAccessor : IMemoryAccess, IDisposable
{
	public nint ProcessHandle { get; }
	public MemoryAccessor(nint hProcess)
	{
		ProcessHandle = hProcess;
	}

	public unsafe MemoryBasicInformation Query(nint address)
	{
		if (!VirtualQueryEx(ProcessHandle, address, out var mbi, sizeof(MemoryBasicInformation)))
			throw new QueryMemoryFailureException(address);
		return mbi;
	}

	public unsafe void WriteMemory(nint address, ReadOnlySpan<byte> buffer)
	{
		int lpNumberOfBytesRead;
		var protection = Query(address).Protect;

		if (protection.HasWriteAccess())
		{
			fixed (byte* b = buffer)
				WriteProcessMemory(ProcessHandle, address, b, buffer.Length, out lpNumberOfBytesRead);
		}
		else
		{
			var newProtect = GetWriteProtection(protection);

			VirtualProtectEx(ProcessHandle, address, buffer.Length, newProtect, out var old);
			fixed (byte* b = buffer)
				WriteProcessMemory(ProcessHandle, address, b, buffer.Length, out lpNumberOfBytesRead);
			VirtualProtectEx(ProcessHandle, address, buffer.Length, old, out old);
		}

		if (lpNumberOfBytesRead != buffer.Length)
			throw new WriteMemoryFailureException(address, buffer.Length);
	}

	public unsafe void ReadMemory(nint address, Span<byte> buffer)
	{
		int lpNumberOfBytesRead;

		var protection = Query(address).Protect;

		if (protection.HasReadAccess())
		{
			fixed (byte* b = buffer)
				ReadProcessMemory(ProcessHandle, address, b, buffer.Length, out lpNumberOfBytesRead);
		}
		else
		{
			var newProtect = GetReadProtection(protection);

			VirtualProtectEx(ProcessHandle, address, buffer.Length, newProtect, out var old);
			fixed (byte* b = buffer)
				ReadProcessMemory(ProcessHandle, address, b, buffer.Length, out lpNumberOfBytesRead);
			VirtualProtectEx(ProcessHandle, address, buffer.Length, old, out old);
		}

		var err = Marshal.GetLastWin32Error();
		if (lpNumberOfBytesRead != buffer.Length)
			throw new ReadMemoryFailureException(address, buffer.Length);
	}

	private static MemoryProtection GetWriteProtection(MemoryProtection existing)
		=> existing.HasWriteAccess() ? existing
		: existing.HasExecuteAccess() ? MemoryProtection.ExecuteReadWrite
		: MemoryProtection.ReadWrite;

	private static MemoryProtection GetReadProtection(MemoryProtection existing)
		=> existing.HasReadAccess() ? existing
		: existing.HasExecuteAccess() ? MemoryProtection.ExecuteRead
		: MemoryProtection.ReadOnly;

	private bool disposed = false;
	public void Dispose()
	{
		Dispose(true);
		GC.SuppressFinalize(this);
	}

	protected virtual void Dispose(bool disposing)
	{
		if (!disposed)
		{
			CloseHandle(ProcessHandle);
			disposed = true;
		}
	}

	~MemoryAccessor()
	{
		Dispose(false);
	}
}
