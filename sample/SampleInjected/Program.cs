using InjectDotnet.NativeHelper;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

//Must use blitable types in UnmanagedCallersOnly delegates

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
		WriteFileHook
			= Process
			.GetCurrentProcess()
			.MainModule
			?.GetImportByName("kernel32", "WriteFile")
			?.Hook(WriteFile_hook);

		//Create a managed delegate for the original kernel32.WriteFile that can be called from inside the hook
		if (WriteFileHook is not null)
			WriteFile_original = Marshal
			.GetDelegateForFunctionPointer<WriteFileDelegate>(WriteFileHook.OriginalFunction);


		//Hook kernel32.CreateFileW
		delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> hook2 = &CreateFileW_hook;
		CreateFileWHook
			= Process
			.GetCurrentProcess()
			.GetModulesByName("kernel32")
			.FirstOrDefault()
			?.GetExportByName("CreateFileW")
			?.Hook(hook2, installAfterCreate: false);
		//Some highly-trafficed functions may be called after the hook is installed but
		//before the delegate to the original funciton is created. You can iliminate that
		//race condition by using the installAfterCreate = false option, then installing
		//the hook after the delegate has been created.

		if (CreateFileWHook?.OriginalFunction is not null or 0)
		{
			CreateFileW_original =
				(delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr>)
				CreateFileWHook.OriginalFunction;

			CreateFileWHook.InstallHook();
		}

		Application.Run(form);

		return 0;
	}

	static ImportHook? WriteFileHook;
	static ExportHook? CreateFileWHook;
	static WriteFileDelegate? WriteFile_original;
	static delegate* unmanaged[Stdcall]<IntPtr, uint, uint, IntPtr, uint, uint, IntPtr, IntPtr> CreateFileW_original;

	delegate bool WriteFileDelegate(IntPtr hFile, byte* lpBuffer, int nNumberOfBytesToWrite, ref int lpNumberOfBytesWritten, IntPtr lpOverlapped);

	//Stdcall is the default export calling convention on x86 platforms. x64 only supports
	//fastcall, so all calling conventions map to fastcall when compiled for x64.
	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	static IntPtr CreateFileW_hook(IntPtr lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile)
	{
		var fileName = new string(MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)lpFileName));

		if (!CreateFileWHook!.HasTrampoline)
		{
			//Trampoline was not created, so remove hook before calling original
			CreateFileWHook!.RemoveHook();
		}

		var result
			= CreateFileW_original(
				lpFileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile);

		if (!CreateFileWHook.HasTrampoline)
		{
			//Trampoline was not created, so reinstall hook after calling original
			CreateFileWHook.InstallHook();
		}

		return result;
	}

	static bool WriteFile_hook(IntPtr hFile, byte* lpBuffer, int nNumberOfBytesToWrite, ref int NumberOfBytesWritten, IntPtr lpOverlapped)
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


		bool result;
		//Call the real WriteFile function.
		fixed (byte* b = replacementBytes)
		{
			result = WriteFile_original!(hFile, b, replacementBytes.Length, ref NumberOfBytesWritten, lpOverlapped);
		}

		if (result)
		{
			//Lie to the caller about the number of bytes written
			NumberOfBytesWritten = nNumberOfBytesToWrite;
		}

		return result;
	}
}