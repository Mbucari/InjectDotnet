using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

//Must use blitable types in UnmanagedCallersOnly delegates
using BOOL = System.Int32;

namespace SampleInjected
{
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


			//Hook kernel32.WriteFile in the main module's import table
			delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL> hook = &WriteFile_hook;

			nint orig;
			if (HookImport.InstallHook(null, "kernel32.dll", "WriteFile", (nint)hook, &orig))
				WriteFile_original = (delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL>)orig;

			Application.Run(form);

			return 0;
		}

		//Stdcall is the default export calling convention on x86 platforms. x64 only supports
		//fastcall, so all calling conventions map to fastcall when compiled for x64.
		static delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL> WriteFile_original;

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

			int result;
			//Call the real WriteFile function.
			fixed (byte* b = replacementBytes)
				result = WriteFile_original(hFile, b, replacementBytes.Length, lpNumberOfBytesWritten, lpOverlapped);

			if (result == 1)
			{
				//Lie to the caller about the number of bytes written
				*lpNumberOfBytesWritten = nNumberOfBytesToWrite;
			}

			return result;
		}

		[STAThread]
		static unsafe void Main()
		{
			var mod = Process.GetCurrentProcess().Modules.Cast<ProcessModule>().ElementAt(4);
			var imports = HookImport.GetModuleImports(mod);
			ApplicationConfiguration.Initialize();
			Application.Run(new Form1());
		}
	}
}