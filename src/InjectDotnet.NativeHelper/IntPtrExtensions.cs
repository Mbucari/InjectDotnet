using System;

#if !NET
	using nint = System.IntPtr;
#endif

namespace InjectDotnet.NativeHelper
{
	internal static class IntPtrExtensions
	{
		public static bool Lt(this nint value, nint other)
		{
#if NET
			return value < other;
#elif X64
			return value.ToInt64() < other.ToInt64();
#elif X86
			return value.ToInt32() < other.ToInt32();
#endif
		}

		public static bool Le(this nint value, nint other)
		{
#if NET
			return value <= other;
#elif X64
			return value.ToInt64() <= other.ToInt64();
#elif X86
			return value.ToInt32() <= other.ToInt32();
#endif
		}

		public static bool Gt(this nint value, nint other)
		{
#if NET
			return value > other;
#elif X64
			return value.ToInt64() > other.ToInt64();
#elif X86
			return value.ToInt32() > other.ToInt32();
#endif
		}

		public static bool Ge(this nint value, nint other)
		{
#if NET
			return value >= other;
#elif X64
			return value.ToInt64() >= other.ToInt64();
#elif X86
			return value.ToInt32() >= other.ToInt32();
#endif
		}

		public static nint Add(this nint value, int other)
			=> IntPtr.Add(value, other);

		public static nint Add(this nint value, nint other)
		{
#if NET
			return value + other;
#elif X64
			return new IntPtr(value.ToInt64() + other.ToInt64());
#elif X86
			return new IntPtr(value.ToInt32() + other.ToInt32());
#endif
		}

		public static nint Mul(this nint value, nint other)
		{
#if NET
			return value * other;
#elif X64
			return new IntPtr(value.ToInt64() * other.ToInt64());
#elif X86
			return new IntPtr(value.ToInt32() * other.ToInt32());
#endif
		}

		public static nint Div(this nint value, nint other)
		{
#if NET
			return value / other;
#elif X64
			return new IntPtr(value.ToInt64() / other.ToInt64());
#elif X86
			return new IntPtr(value.ToInt32() / other.ToInt32());
#endif
		}

		public static nint Subtract(this nint value, nint other)
		{
#if NET
			return value - other;
#elif X64
			return new IntPtr(value.ToInt64() - other.ToInt64());
#elif X86
			return new IntPtr(value.ToInt32() - other.ToInt32());
#endif
		}

		public static nint Or(this nint value, nint other)
		{
#if NET
			return value | other;
#elif X64
			return new IntPtr(value.ToInt64() | other.ToInt64());
#elif X86
			return new IntPtr(value.ToInt32() | other.ToInt32());
#endif
		}

		public static nint And(this nint value, nint other)
		{
#if NET
			return value & other;
#elif X64
			return new IntPtr(value.ToInt64() & other.ToInt64());
#elif X86
			return new IntPtr(value.ToInt32() & other.ToInt32());
#endif
		}

		public static nint Lsh(this nint value, int count)
		{
#if NET
			return value << count;
#elif X64
			return new IntPtr(value.ToInt64() << count);
#elif X86
			return new IntPtr(value.ToInt32() << count);
#endif
		}

		public static nint Rsh(this nint value, int count)
		{
#if NET
			return value >> count;
#elif X64
			return new IntPtr(value.ToInt64() >> count);
#elif X86
			return new IntPtr(value.ToInt32() >> count);
#endif
		}

		public static nint Not(this nint value)
		{
#if NET
			return ~value;
#elif X64
			return new IntPtr(~value.ToInt64());
#elif X86
			return new IntPtr(~value.ToInt32());
#endif
		}
	}
}