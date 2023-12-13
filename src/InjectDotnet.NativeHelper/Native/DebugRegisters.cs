using System;
using System.Runtime.InteropServices;

#if !NET
using nint = System.IntPtr;
#endif

namespace InjectDotnet.NativeHelper.Native
{
	public enum BreakEnabled : byte
	{
		Disabled,
		Local,
		Global
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
		public DebugRegister DetectedBreakCondition
		{
			get
			{
				switch ((int)_dr6 & 0xf) 
				{
					case 1: return DebugRegister.Dr0;
					case 2: return DebugRegister.Dr1;
					case 4: return DebugRegister.Dr2;
					case 8: return DebugRegister.Dr3;
					default: return DebugRegister.None;
				}
			}
		}

		public bool SingleStepExecution
		{
			get => ((int)_dr6 & SINGLE_STEP_FLAG) == SINGLE_STEP_FLAG;
			set { if (value) _dr6 = _dr6.Or((nint)SINGLE_STEP_FLAG); else _dr6 = _dr6.And((nint)~SINGLE_STEP_FLAG); }
		}

		public nint GetAddress(DebugRegister register)
		{
			switch (register)
			{
				case DebugRegister.Dr0: return _dr0;
				case DebugRegister.Dr1: return _dr1;
				case DebugRegister.Dr2: return _dr2;
				case DebugRegister.Dr3: return _dr3;
				default: throw new InvalidOperationException();
			}
		}

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
			_dr7 = _dr7.And(((nint)3).Lsh(16 + 4 * regNum).Not());
			_dr7 = _dr7.Or(((nint)condition).Lsh(16 + 4 * regNum));
		}

		public void SetLength(DebugRegister register, BreakLength length)
		{
			var regNum = (int)register;
			_dr7 = _dr7.And(((nint)3).Lsh(18 + 4 * regNum).Not());
			_dr7 = _dr7.Or(((nint)length).Lsh(18 + 4 * regNum));
		}

		public void SetEnabled(DebugRegister register, BreakEnabled enabled)
		{
			var regNum = (int)register;
			_dr7 = _dr7.And(((nint)3).Lsh(2 * regNum).Not());
			_dr7 = _dr7.Or(((nint)enabled).Lsh(2 * regNum));
		}

		public BreakCondition GetCondition(DebugRegister register)
		{
			var regNum = (int)register;
			return (BreakCondition)_dr7.Rsh(16 + 4 * regNum).And((nint)0x3);
		}

		public BreakEnabled GetEnabled(DebugRegister register)
		{
			var regNum = (int)register;
			return (BreakEnabled)_dr7.Rsh(2 * regNum).And((nint)0x3);
		}

		public BreakLength GetLength(DebugRegister register)
		{
			var regNum = (int)register;
			return (BreakLength)_dr7.Rsh(18 + 4 * regNum).And((nint)0x3);
		}

		public nint Dr0Address
		{
			get => GetAddress(DebugRegister.Dr0);
			set => SetAddress(DebugRegister.Dr0, value);
		}

		public nint Dr1Address
		{
			get => GetAddress(DebugRegister.Dr1);
			set => SetAddress(DebugRegister.Dr1, value);
		}

		public nint Dr2Address
		{
			get => GetAddress(DebugRegister.Dr2);
			set => SetAddress(DebugRegister.Dr2, value);
		}

		public nint Dr3Address
		{
			get => GetAddress(DebugRegister.Dr3);
			set => SetAddress(DebugRegister.Dr3, value);
		}

		public BreakCondition Dr0Condition
		{
			get => GetCondition(DebugRegister.Dr0);
			set => SetCondition(DebugRegister.Dr0, value);
		}

		public BreakLength Dr0Length
		{
			get => GetLength(DebugRegister.Dr0);
			set => SetLength(DebugRegister.Dr0, value);
		}

		public BreakCondition Dr1Condition
		{
			get => GetCondition(DebugRegister.Dr1);
			set => SetCondition(DebugRegister.Dr1, value);
		}

		public BreakLength Dr1Length
		{
			get => GetLength(DebugRegister.Dr1);
			set => SetLength(DebugRegister.Dr1, value);
		}

		public BreakCondition Dr2Condition
		{
			get => GetCondition(DebugRegister.Dr2);
			set => SetCondition(DebugRegister.Dr2, value);
		}

		public BreakLength Dr2Length
		{
			get => GetLength(DebugRegister.Dr2);
			set => SetLength(DebugRegister.Dr2, value);
		}

		public BreakCondition Dr3Condition
		{
			get => GetCondition(DebugRegister.Dr3);
			set => SetCondition(DebugRegister.Dr3, value);
		}

		public BreakLength Dr3Length
		{
			get => GetLength(DebugRegister.Dr3);
			set => SetLength(DebugRegister.Dr3, value);
		}

		public BreakEnabled Dr0Enabled
		{
			get => GetEnabled(DebugRegister.Dr0);
			set => SetEnabled(DebugRegister.Dr0, value);
		}

		public BreakEnabled Dr1Enabled
		{
			get => GetEnabled(DebugRegister.Dr1);
			set => SetEnabled(DebugRegister.Dr1, value);
		}

		public BreakEnabled Dr2Enabled
		{
			get => GetEnabled(DebugRegister.Dr2);
			set => SetEnabled(DebugRegister.Dr2, value);
		}

		public BreakEnabled Dr3Enabled
		{
			get => GetEnabled(DebugRegister.Dr3);
			set => SetEnabled(DebugRegister.Dr3, value);
		}

		public override string ToString()
		{
			long temp = 1L << 32 | (uint)_dr7;
			return Convert.ToString(temp, 2).Substring(1);
		}
	}
}