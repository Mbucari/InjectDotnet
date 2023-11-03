using InjectDotnet.Native;
using System;
using System.Runtime.InteropServices;

namespace InjectDotnet.Debug;

public static class DebuggerExtensions
{
	public static nint WriteMemory(this Debugger debugger, string argument)
		=> debugger.WriteMemory(MemoryMarshal.AsBytes(argument.AsSpan()));

	public static nint AllocateMemory(this Debugger debugger, nint size, MemoryProtection memoryProtection = MemoryProtection.ExecuteReadWrite)
	{
		return NativeMethods.VirtualAllocEx(debugger.ProcessInfo.ProcessHandle, 0, size, AllocationType.ReserveCommit, memoryProtection);
	}
	public static unsafe nint WriteMemory(this Debugger debugger, ReadOnlySpan<byte> buffer, MemoryProtection protection = MemoryProtection.ReadWrite)
	{
		var baseAddress = debugger.AllocateMemory(buffer.Length, protection);
		debugger.MemoryAccess.WriteMemory(baseAddress, buffer);
		return baseAddress;
	}
}
