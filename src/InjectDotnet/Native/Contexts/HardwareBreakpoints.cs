using System;
using System.Runtime.InteropServices;

namespace InjectDotnet.Native;

public enum BreakEnabled : byte
{
	Disabled = 0,
	Local = 1,
	Global = 2
}

public enum BreakCondition : byte
{
	Execute,
	Write,
	ReadWrite_IO,
	ReadWrite_Data,
}

public enum BreakLength : byte
{
	Byte,
	Word,
	QWord,
	DWord,
}

public enum DebugRegister : int
{
	None = -1, Dr0, Dr1, Dr2, Dr3
}

[StructLayout(LayoutKind.Sequential)]
public struct DebugRegisters
{
	private nint _dr0;
	private nint _dr1;
	private nint _dr2;
	private nint _dr3;
	private nint _dr6;
	private nint _dr7;

	private const int SINGLE_STEP_FLAG = 0x4000;

	/// <summary>
	/// Returns the debug register number on which the break occurred, or -1 if none.
	/// </summary>
	public readonly DebugRegister DetectedBreakCondition
	=> (_dr6 & 0xf) switch
	{
		1 => DebugRegister.Dr0,
		2 => DebugRegister.Dr1,
		4 => DebugRegister.Dr2,
		8 => DebugRegister.Dr3,
		_ => DebugRegister.None
	};

	public bool SingleStepExecution
	{
		readonly get => (_dr6 & SINGLE_STEP_FLAG) == SINGLE_STEP_FLAG;
		set { if (value) _dr6 |= SINGLE_STEP_FLAG; else _dr6 &= ~SINGLE_STEP_FLAG; }
	}

	public readonly nint GetAddress(DebugRegister register) => register switch
	{
		DebugRegister.Dr0 => _dr0,
		DebugRegister.Dr1 => _dr1,
		DebugRegister.Dr2 => _dr2,
		DebugRegister.Dr3 => _dr3,
		_ => throw new InvalidOperationException()
	};

	public void SetAddress(DebugRegister register, nint Address)
	{
		switch (register)
		{
			case DebugRegister.Dr0:
				_dr0 = Address;
				break;
			case DebugRegister.Dr1:
				_dr1 = Address;
				break;
			case DebugRegister.Dr2:
				_dr2 = Address;
				break;
			case DebugRegister.Dr3:
				_dr3 = Address;
				break;
			default:
				throw new InvalidOperationException();
		}
	}

	public void SetCondition(DebugRegister register, BreakCondition condition)
	{
		var regNum = (int)register;
		_dr7 &= ~((nint)3 << (16 + 4 * regNum));
		_dr7 |= (nint)condition << (16 + 4 * regNum);
	}
	public void SetLength(DebugRegister register, BreakLength length)
	{
		var regNum = (int)register;
		_dr7 &= ~((nint)3 << (18 + 4 * regNum));
		_dr7 |= (nint)length << (18 + 4 * regNum);
	}
	public void SetEnabled(DebugRegister register, BreakEnabled enabled)
	{
		var regNum = (int)register;
		_dr7 &= ~((nint)3 << (2 * regNum));
		_dr7 |= (nint)enabled << (2 * regNum);
	}
	public readonly BreakCondition GetCondition(DebugRegister register)
	{
		var regNum = (int)register;
		return (BreakCondition)((_dr7 >> (16 + 4 * regNum)) & 0x3);
	}

	public readonly BreakEnabled GetEnabled(DebugRegister register)
	{
		var regNum = (int)register;
		return (BreakEnabled)((_dr7 >> (2 * regNum)) & 0x3);
	}

	public readonly BreakLength GetLength(DebugRegister register)
	{
		var regNum = (int)register;
		return (BreakLength)((_dr7 >> (18 + 4 * regNum)) & 0x3);
	}

	public nint Dr0Address
	{
		readonly get => GetAddress(DebugRegister.Dr0);
		set => SetAddress(DebugRegister.Dr0, value);
	}
	public nint Dr1Address
	{
		readonly get => GetAddress(DebugRegister.Dr1);
		set => SetAddress(DebugRegister.Dr1, value);
	}
	public nint Dr2Address
	{
		readonly get => GetAddress(DebugRegister.Dr2);
		set => SetAddress(DebugRegister.Dr2, value);
	}
	public nint Dr3Address
	{
		readonly get => GetAddress(DebugRegister.Dr3);
		set => SetAddress(DebugRegister.Dr3, value);
	}

	public BreakCondition Dr0Condition
	{
		readonly get => GetCondition(DebugRegister.Dr0);
		set => SetCondition(DebugRegister.Dr0, value);
	}

	public BreakLength Dr0Length
	{
		readonly get => GetLength(DebugRegister.Dr0);
		set => SetLength(DebugRegister.Dr0, value);
	}

	public BreakCondition Dr1Condition
	{
		readonly get => GetCondition(DebugRegister.Dr1);
		set => SetCondition(DebugRegister.Dr1, value);
	}

	public BreakLength Dr1Length
	{
		readonly get => GetLength(DebugRegister.Dr1);
		set => SetLength(DebugRegister.Dr1, value);
	}

	public BreakCondition Dr2Condition
	{
		readonly get => GetCondition(DebugRegister.Dr2);
		set => SetCondition(DebugRegister.Dr2, value);
	}

	public BreakLength Dr2Length
	{
		readonly get => GetLength(DebugRegister.Dr2);
		set => SetLength(DebugRegister.Dr2, value);
	}

	public BreakCondition Dr3Condition
	{
		readonly get => GetCondition(DebugRegister.Dr3);
		set => SetCondition(DebugRegister.Dr3, value);
	}

	public BreakLength Dr3Length
	{
		readonly get => GetLength(DebugRegister.Dr3);
		set => SetLength(DebugRegister.Dr3, value);
	}

	public BreakEnabled Dr0Enabled
	{
		readonly get => GetEnabled(DebugRegister.Dr0);
		set => SetEnabled(DebugRegister.Dr0, value);
	}

	public BreakEnabled Dr1Enabled
	{
		readonly get => GetEnabled(DebugRegister.Dr1);
		set => SetEnabled(DebugRegister.Dr1, value);
	}

	public BreakEnabled Dr2Enabled
	{
		readonly get => GetEnabled(DebugRegister.Dr2);
		set => SetEnabled(DebugRegister.Dr2, value);
	}

	public BreakEnabled Dr3Enabled
	{
		readonly get => GetEnabled(DebugRegister.Dr3);
		set => SetEnabled(DebugRegister.Dr3, value);
	}

	public override readonly string ToString()
	{
		long temp = 1L << 32 | (uint)_dr7;
		return Convert.ToString(temp, 2).Substring(1);
	}
}