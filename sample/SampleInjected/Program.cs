using InjectDotnet.NativeHelper;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

//Must use blitable types in UnmanagedCallersOnly delegates
using BOOL = System.Int32;

namespace SampleInjected;

struct Argument
{
#pragma warning disable CS0649 // Field is never assigned to, and will always have its default value
	public IntPtr Title;
	public IntPtr Text;
	public IntPtr Picture;
	public int pic_sz;
#pragma warning restore CS0649
}

internal unsafe static class Program
{
	[DllImport("kernel32", CharSet = CharSet.Unicode, ExactSpelling = true)]
	public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, uint dwFreeType);

	[DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
	static extern int GetFinalPathNameByHandleW(IntPtr hFile, char* lpszFilePath, int cchFilePath, uint dwFlags);


	[STAThread]
	public static int Bootstrap(IntPtr argument, int size)
	{
		//load the struct from unmanaged memory
		var arg = Marshal.PtrToStructure<Argument>(argument);

		var title = new string(MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)arg.Title));
		var text = new string(MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)arg.Text));
		var pic = new byte[arg.pic_sz];
		Marshal.Copy(arg.Picture, pic, 0, pic.Length);

		//Free all arguments from native memory.
		//The loader handles freeing the argument struct
		VirtualFree(arg.Title, 0, 0x8000);
		VirtualFree(arg.Text, 0, 0x8000);
		VirtualFree(arg.Picture, 0, 0x8000);

		ApplicationConfiguration.Initialize();

		using var ms = new MemoryStream(pic);
		Image img = Image.FromStream(ms);

		var form = new Form1
		{
			Text = new string(title)
		};
		form.label1.Text = text;
		form.pictureBox1.Image = img;

		var currentProc = Process.GetCurrentProcess();

		//Hook kernel32.WriteFile in the main module's import table
		delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL> hook1 = &WriteFile_hook;
		WriteFileHook
			= currentProc
			.MainModule
			?.GetImportByName("kernel32", "WriteFile")
			?.Hook((nint)hook1);

		//Hook kernel32.CreateFileW
		delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> hook2 = &CreateFileW_hook;
		CreateFileWHook
			= currentProc
			.GetModulesByName("kernel32")
			.FirstOrDefault()
			?.GetExportByName("CreateFileW")
			?.Hook((nint)hook2);

		Application.Run(form);

		return 0;
	}

	static ImportHook? WriteFileHook;
	static ExportHook? CreateFileWHook;

	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	static IntPtr CreateFileW_hook(IntPtr lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile)
	{
		var fileName = new string(MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)lpFileName));

		CreateFileWHook!.RemoveHook();

		var result = ((delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr>)CreateFileWHook.OriginalFunction)
			(
			lpFileName,
			dwDesiredAccess,
			dwShareMode,
			lpSecurityAttributes,
			dwCreationDisposition,
			dwFlagsAndAttributes,
			hTemplateFile
			);

		CreateFileWHook.InstallHook();
		return result;
	}

	//Stdcall is the default export calling convention on x86 platforms. x64 only supports
	//fastcall, so all calling conventions map to fastcall when compiled for x64.
	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	static BOOL WriteFile_hook(IntPtr hFile, byte* lpBuffer, int nNumberOfBytesToWrite, int* lpNumberOfBytesWritten, IntPtr lpOverlapped)
	{
		//Get the filename being written to
		var sz = GetFinalPathNameByHandleW(hFile, null, 0, 0);
		Span<char> buff = new char[sz];
		fixed (char* c = buff)
			sz = GetFinalPathNameByHandleW(hFile, c, buff.Length, 0);

		var fileName = new string(buff.Slice(0, sz));

		//Peek at the bytes to be written
		var bytesToWrite = new Span<byte>(lpBuffer, nNumberOfBytesToWrite);

		//Write different data
		var replacementBytes = Encoding.ASCII.GetBytes("WriteFile was intercepted and modified!");

		BOOL result;
		//Call the real WriteFile function.
		fixed (byte* b = replacementBytes)
		{
			result = ((delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL>)WriteFileHook!.OriginalFunction)
			(
				hFile,
				b,
				replacementBytes.Length,
				lpNumberOfBytesWritten,
				lpOverlapped
			);
		}

		if (result == 1)
		{
			//Lie to the caller about the number of bytes written
			*lpNumberOfBytesWritten = nNumberOfBytesToWrite;
		}

		//Remove the import hook
		WriteFileHook.RemoveHook();

		return result;
	}

	[STAThread]
	static unsafe void Main()
	{
		var type = typeof(delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL>);
		var mods = Process.GetCurrentProcess().GetModulesByName("kernel32").FirstOrDefault().GetExportByName("FindClose").Hook(1);

		ApplicationConfiguration.Initialize();
		Application.Run(new Form1());
	}
}