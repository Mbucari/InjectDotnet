using System;

namespace InjectDotnet.Native;

/// <summary>
/// Interface to provide reqd/write/query access to target
/// </summary>
public interface IMemoryAccess : IMemoryReader, IMemoryWriter
{
	/// <summary>
	/// Query basic memory information about the target address
	/// </summary>
	/// <param name="address">target address to query memory basic information</param>
	/// <returns>Memory basic information for the target address</returns>
	/// <exception cref="QueryMemoryFailureException">Throws if can't query the memory</exception>
	MemoryBasicInformation Query(nint address);
}

/// <summary>
/// Interface to provide write access to target
/// </summary>
public interface IMemoryWriter
{
	/// <summary>
	/// Write memory to the target process. Either reads all memory or throws.
	/// </summary>
	/// <param name="address">target address to read memory from</param>
	/// <param name="buffer">buffer to write to target</param>
	/// <exception cref="ReadMemoryFailureException">Throws if can't read all the memory</exception>
	void WriteMemory(nint address, ReadOnlySpan<byte> buffer);
}


/// <summary>
/// Interface to provide read access to target
/// </summary>
public interface IMemoryReader
{
	/// <summary>
	/// Read memory from the target process. Either reads all memory or throws.
	/// </summary>
	/// <param name="address">target address to read memory from</param>
	/// <param name="buffer">buffer to fill with memory</param>
	/// <exception cref="ReadMemoryFailureException">Throws if can't read all the memory</exception>
	void ReadMemory(nint address, Span<byte> buffer);
}

/// <summary>
/// Thrown when failing to read memory from a target.
/// </summary>
[Serializable]
public class ReadMemoryFailureException : InvalidOperationException
{
	/// <summary>
	/// Initialize a new exception
	/// </summary>
	/// <param name="address">address where read failed</param>
	/// <param name="countBytes">size of read attempted</param>
	public ReadMemoryFailureException(IntPtr address, int countBytes)
		: base(MessageHelper(address, countBytes))
	{
	}

	public ReadMemoryFailureException(IntPtr address, int countBytes, Exception innerException)
		: base(MessageHelper(address, countBytes), innerException)
	{
	}

	// Internal helper to get the message string for the ctor.
	static string MessageHelper(IntPtr address, int countBytes)
	{
		return String.Format("Failed to read memory at 0x" + address.ToString("x") + " of " + countBytes + " bytes.");
	}
}

/// <summary>
/// Thrown when failing to query memory from a target.
/// </summary>
[Serializable]
public class QueryMemoryFailureException : InvalidOperationException
{
	/// <summary>
	/// Initialize a new exception
	/// </summary>
	/// <param name="address">address where query failed</param>
	/// <param name="countBytes">size of query attempted</param>
	public QueryMemoryFailureException(IntPtr address)
		: base(MessageHelper(address))
	{
	}

	public QueryMemoryFailureException(IntPtr address, Exception innerException)
		: base(MessageHelper(address), innerException)
	{
	}

	// Internal helper to get the message string for the ctor.
	static string MessageHelper(IntPtr address)
	{
		return String.Format("Failed to query memory at 0x" + address.ToString("x"));
	}
}
/// <summary>
/// Thrown when failing to read memory from a target.
/// </summary>
[Serializable]
public class WriteMemoryFailureException : InvalidOperationException
{
	/// <summary>
	/// Initialize a new exception
	/// </summary>
	/// <param name="address">address where read failed</param>
	/// <param name="countBytes">size of read attempted</param>
	public WriteMemoryFailureException(IntPtr address, int countBytes)
		: base(MessageHelper(address, countBytes))
	{
	}

	public WriteMemoryFailureException(IntPtr address, int countBytes, Exception innerException)
		: base(MessageHelper(address, countBytes), innerException)
	{
	}

	// Internal helper to get the message string for the ctor.
	static string MessageHelper(IntPtr address, int countBytes)
	{
		return string.Format("Failed to write memory at 0x" + address.ToString("x") + " of " + countBytes + " bytes.");
	}
}
