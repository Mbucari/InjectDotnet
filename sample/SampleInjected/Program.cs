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
		public IntPtr Title;
		public IntPtr Text;
		public IntPtr Picture;
		public int pic_sz;
	}

	internal unsafe static class Program
	{
		[DllImport("kernel32.dll")]
		static extern bool VirtualProtect(IntPtr handle, int size, uint newProtect, uint* oldProtect);

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


			//Hook native function kernel32.WriteFile
			delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL> hook = &WriteFile_hook;

			nint orig;
			if (HookImport("kernel32.dll", "WriteFile", (nint)hook, &orig))
				WriteFile_original = (delegate* unmanaged[Stdcall]<IntPtr, byte*, int, int*, IntPtr, BOOL>)orig;

			Application.Run(form);

			return 0;
		}

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

		/// <summary>
		/// Replace an imported function with a delegate
		/// </summary>
		/// <param name="moduleName">Name of the imported library containing the function to hook</param>
		/// <param name="functionName">Name of the function to hook</param>
		/// <param name="hookFunction">Pointer to a manager delegate that will be called instead of <paramref name="functionName"/></param>
		/// <param name="originalFunction">Pointer to the function being hooked</param>
		/// <returns>Success</returns>
		private static bool HookImport(string moduleName, string functionName, nint hookFunction, nint* originalFunction)
		{
			var mainModule = Process.GetCurrentProcess().MainModule;

			if (mainModule?.FileName is null
				|| !PeNet.PeFile.TryParse(mainModule.FileName, out var pe)
				|| pe!.ImageImportDescriptors is null)
				return false;

			nint hModule = mainModule.BaseAddress;

			//Iterate over all modules in the program's import table
			foreach (var des in pe.ImageImportDescriptors)
			{
				//Import name
				var libName = new string((sbyte*)(hModule + des.Name));

				if (libName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
				{
					var pOT = (nint*)(hModule + des.OriginalFirstThunk);
					var pImportTableEntry = (nint*)(hModule + des.FirstThunk);

					//Iterate over all imported functions in the library
					while (*pOT > 0)
					{
						var funcName = new string((sbyte*)(hModule + *pOT + 2));

						if (funcName.Equals(functionName, StringComparison.OrdinalIgnoreCase))
						{
							*originalFunction = *pImportTableEntry;

							uint oldProtect;
							//Change IAT protection to read-write
							VirtualProtect((nint)pImportTableEntry, sizeof(nint), 4u, &oldProtect);
							//Replace the original function pointer in the IAT with the hook pointer;
							*pImportTableEntry = hookFunction;
							//Restore IAT's protection
							VirtualProtect((nint)pImportTableEntry, sizeof(nint), oldProtect, &oldProtect);
							return true;
						}

						pOT++;
						pImportTableEntry++;
					}
					return false;
				}
			}
			return false;
		}

		[STAThread]
		static void Main()
		{
			ApplicationConfiguration.Initialize();
			Application.Run(new Form1());
		}
	}
}