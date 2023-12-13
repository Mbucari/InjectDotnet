using InjectDotnet.NativeHelper.Native;

#if !NET
using nint = System.IntPtr;
#endif

namespace InjectDotnet.NativeHelper.Breakpoints
{
	/// <summary>
	/// Represents one of the possible four hardware breakpoints for a thread in this process.
	/// </summary>
	public class Breakpoint
	{
		private nint _address;
		private DebugRegister _register;
		private BreakCondition _condition;
		private BreakLength _length;
		private BreakEnabled _enabled;

		/// <summary>
		/// The <see cref="ThreadBreakpoints"/> to which this <see cref="Breakpoint"/> belongs.
		/// </summary>
		public ThreadBreakpoints ThreadBreakpoints { get; }
		/// <summary>
		/// The <see cref="DebugRegister"/> of this breakpoint
		/// </summary>
		public DebugRegister Register { get => _register; set => SetValue(ref _register, value); }
		/// <summary>
		/// Virtual address to break on.
		/// </summary>
		public nint Address { get => _address; set => SetValue(ref _address, value); }
		/// <summary>
		/// The condition under which te processor will throw a break exception.
		/// </summary>
		public BreakCondition Condition { get => _condition; set => SetValue(ref _condition, value); }
		/// <summary>
		/// Breakpoint length. <see cref="BreakLength.QWord"/> is undefined on 32-bit mode.
		/// </summary>
		public BreakLength Length { get => _length; set => SetValue(ref _length, value); }
		/// <summary>
		/// Enabled status.
		/// </summary>
		public BreakEnabled Enabled { get => _enabled; set => SetValue(ref _enabled, value); }
		/// <summary>
		/// The instruction pointer where execution will resume after continuing.
		/// </summary>
		public nint ResumeIP { get; set; }

		internal Breakpoint(ThreadBreakpoints threadBP, DebugRegister register)
		{
			ThreadBreakpoints = threadBP;
			Register = register;
		}

		private T SetValue<T>(ref T field, T newValue)
		{
			if (field?.Equals(newValue) != true)
			{
				field = newValue;
				ThreadBreakpoints.BreakpointNeedsSetting = true;
			}
			return field;
		}
	}
}