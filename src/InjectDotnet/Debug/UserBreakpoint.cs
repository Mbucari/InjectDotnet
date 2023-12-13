using InjectDotnet.Native;
using System;

namespace InjectDotnet.Debug;

public class UserBreakpoint
{
	/// <summary>
	/// Memory address of the breakpoint
	/// </summary>
	public nint Address { get; }
	/// <summary>
	/// User-defined breakpoint name
	/// </summary>
	public string? Name { get; }
	/// <summary>
	/// Gets or sets a value indicating whether this breakpoint is automatically reset after it has been hit.
	/// </summary>
	public bool AutoReset { get; set; } = true;
	/// <summary>
	/// Indicates whether this breakpoint is enabled in the target process.
	/// </summary>
	public bool Enabled { get; private set; }
	/// <summary>
	/// The number of time ths breakpoint has been hit.
	/// </summary>
	public int HitCount { get; internal set; }

	/// <summary>
	/// Indicates whether the debugger raises <see cref="Debugger.Breakpoint"/>
	/// for single-stepping to reset an <see cref="AutoReset"/> breakpoint. 
	/// </summary>
	internal bool NotifySingleStep { get; set; }

	private byte? OriginalCode;
	private const byte INT3 = 0xcc;
	private readonly IMemoryAccess Accessor;

	internal UserBreakpoint(nint address, IMemoryAccess accessor, string? name)
	{
		Address = address;
		Accessor = accessor;
		Name = name;
	}

	/// <summary>
	/// Tries to enable the breakpoint in the target process.
	/// </summary>
	/// <returns>A value indicating whether the breakpoint was successfully enabled</returns>
	public bool TryDisable()
	{
		if (!Enabled) return true;
		if (OriginalCode is null) return false;

		try
		{
			Accessor.WriteMemory(Address, new byte[] { OriginalCode.Value });
		}
		catch (InvalidOperationException)
		{
			return false;
		}

		return Enabled = false;
	}

	/// <summary>
	/// Tries to disable the breakpoint in the target process.
	/// </summary>
	/// <returns>A value indicating whether the breakpoint was successfully disabled</returns>
	public bool TryEnable()
	{
		if (Enabled) return true;

		if (OriginalCode is null)
		{
			var original = new byte[1];
			try
			{
				Accessor.ReadMemory(Address, original);
			}
			catch (InvalidOperationException)
			{
				return false;
			}

			if (original[0] == INT3)
				return false;

			OriginalCode = original[0];
		}

		try
		{
			Accessor.WriteMemory(Address, new byte[] { INT3 });
		}
		catch (InvalidOperationException)
		{
			return false;
		}

		return Enabled = true;
	}
}
