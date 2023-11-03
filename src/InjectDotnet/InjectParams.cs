using System.Runtime.InteropServices;

namespace InjectDotnet;

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
	public nint fnLoadLibrary;
	[FieldOffset(0x28)]
	public nint fnGetProcAddress;
	[FieldOffset(0x30)]
	public nint fnEntryPoint;
	[FieldOffset(0x38)]
	readonly nint _context;
	[FieldOffset(0x40)]
	readonly nint _delegate;
	[FieldOffset(0x48)]
	readonly nint _method_fn;

	[FieldOffset(0x50)]
	public nint str_runtimeconfig;
	[FieldOffset(0x58)]
	public nint str_dll_path;
	[FieldOffset(0x60)]
	public nint str_type;
	[FieldOffset(0x68)]
	public nint str_method_name;
	[FieldOffset(0x70)]
	public nint str_hostfxr_path;
	[FieldOffset(0x78)]
	public nint str_Config_name;
	[FieldOffset(0x80)]
	public nint str_GetDelegate_name;
	[FieldOffset(0x88)]
	public nint str_Close_name;
	[FieldOffset(0x90)]
	public nint args;
	[FieldOffset(0x98)]
	public int sz_args;
}
