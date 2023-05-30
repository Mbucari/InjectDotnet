using System.Runtime.InteropServices;

namespace InjectDotnet
{
	[StructLayout(LayoutKind.Explicit)]
	internal struct InjectParams
	{
		[FieldOffset(0)]
		public nint fnConfig;
		[FieldOffset(8)]
		public nint fnGetDelegate;
		[FieldOffset(0x10)]
		public nint fnClose;
		[FieldOffset(0x18)]
		public nint fnVirtualFree;
		[FieldOffset(0x20)]
		public nint fnExitThread;
		[FieldOffset(0x28)]
		nint _context;
		[FieldOffset(0x30)]
		nint _delegate;
		[FieldOffset(0x38)]
		nint _method_fn;
		[FieldOffset(0x40)]
		public nint str_runtimeconfig;
		[FieldOffset(0x48)]
		public nint str_dll_path;
		[FieldOffset(0x50)]
		public nint str_type;
		[FieldOffset(0x58)]
		public nint str_method_name;
		[FieldOffset(0x60)]
		public nint args;
		[FieldOffset(0x68)]
		public int sz_args;
	}
}
