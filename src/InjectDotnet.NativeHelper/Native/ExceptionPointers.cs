#if !NET
using nint = System.IntPtr;
#endif

namespace InjectDotnet.NativeHelper.Native
{
	public unsafe struct ExceptionRecord
	{
		public uint ExceptionCode;
		public uint ExceptionFlags;
		public ExceptionRecord* NextRecord;
		public void* ExceptionAddress;
		public uint NumberParameters;
		public nint ExceptionInformation;
	}

	public unsafe struct ExceptionPointers
	{
		public ExceptionRecord* ExceptionRecord;
		public Context* ContextRecord;
	}
}