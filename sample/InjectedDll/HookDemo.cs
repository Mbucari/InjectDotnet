using InjectDotnet.NativeHelper;
using InjectDotnet.NativeHelper.Native;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

/*
 * This is an example of an injected .NET dll.
 * It demonstrates hooking native functions by all three supported methods:
 * 
 * 1) Import address table hooking
 * 2) Jump hooking
 * 3) Hardware breakpoint hooking.
 */ 


//Must use blittable types in UnmanagedCallersOnly delegates
using BOOL = System.Int32;

namespace InjectedDll;

struct Argument
{
#pragma warning disable CS0649 // Field is never assigned to, and will always have its default value
	public IntPtr Title;
	public IntPtr Text;
	public IntPtr Picture;
	public int pic_sz;
#pragma warning restore CS0649

}

internal static unsafe partial class HookDemo
{

	[LibraryImport("Kernel32.dll", SetLastError = true)]
	private static partial int GetFinalPathNameByHandleW(IntPtr hFile, char* lpszFilePath, int cchFilePath, uint dwFlags);

	/// <summary>
	/// The InjectedDll's entry point.
	/// </summary>
	[STAThread]
	public static int Bootstrap(IntPtr argument, int size)
	{
		#region Load Argument and Create Display Form

		//load the struct from unmanaged memory
		var arg = Marshal.PtrToStructure<Argument>(argument);

		var title = new string(MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)arg.Title));
		var label = new string(MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)arg.Text));
		var pic = new byte[arg.pic_sz];
		Marshal.Copy(arg.Picture, pic, 0, pic.Length);

		using var ms = new MemoryStream(pic);
		Image img = Image.FromStream(ms);

		using var waitHandle = new ManualResetEvent(false);
		var t = new Thread(() => RunForm(waitHandle, title, label, img));
		//Run the form on STA thread so it can use COM
		t.SetApartmentState(ApartmentState.STA);
		t.Start();
		//Wait for the form to finish initializing before continuing
		waitHandle.WaitOne();

		//Free all arguments from native memory.
		//The loader handles freeing the argument struct
		NativeMethods.VirtualFree(arg.Title, 0, FreeType.Release);
		NativeMethods.VirtualFree(arg.Text, 0, FreeType.Release);
		NativeMethods.VirtualFree(arg.Picture, 0, FreeType.Release);

		#endregion

		#region Register Hooks

		using var currentProc = Process.GetCurrentProcess();

		#region Module Import Table Hook

		//Hook kernel32.CloseHandle
		if (currentProc.MainModule?.GetImportByName("kernel32", "CloseHandle") is NativeImport closeHandleImport)
		{
			delegate* unmanaged[Stdcall]<nint, BOOL> hookFn = &CloseHandle;

			//Some highly-trafficked functions may be called after the hookFn is installed but
			//before the delegate to the original function is created. You can eliminate that
			//race condition by using the installAfterCreate = false option, then installing
			//the hookFn after the delegate has been created.
			if (closeHandleImport.Hook(hookFn, installAfterCreate: false) is INativeHook hook)
			{
				CloseHandleHook = hook;
				CloseHandle_original =
				(delegate* unmanaged[Stdcall]<nint, BOOL>)
				hook.OriginalFunction;
				hook.InstallHook();
			}
		}

		#endregion
		#region Trampoline Detour Hook

		var k32 = currentProc.GetModulesByName("kernel32").FirstOrDefault();
		if (k32 is null) return -1;

		//Hook kernel32.ReadFile
		if (k32.GetExportByName("ReadFile") is NativeExport readFileExport)
		{
			if (readFileExport.Hook(ReadFile) is INativeHook hook)
			{
				ReadFileHook = hook;

				ReadFile_original
					= Marshal
					.GetDelegateForFunctionPointer<ReadFileDelegate>(hook.OriginalFunction);
			}
		}

		//Hook kernel32.CreateFileW
		if (k32.GetExportByName("CreateFileW") is NativeExport createFileExport)
		{
			delegate* unmanaged[Stdcall]<nint, FileAccess, FileShare, nint, FileMode, FileAttributes, nint, nint> hookFn = &CreateFileW;

			if (createFileExport.Hook(hookFn, installAfterCreate: false) is INativeHook hook)
			{
				CreateFileWHook = hook;

				CreateFileW_original =
				(delegate* unmanaged[Stdcall]<nint, FileAccess, FileShare, nint, FileMode, FileAttributes, nint, nint>)
				hook.OriginalFunction;
				hook.InstallHook();
			}
		}

		#endregion
		#region Hardware Breakpoint Hook

		//Hook kernel32.WriteFile
		/*
		 * NOTE: You will not be able to debug a breakpoint hook.
		 *	The attached debugger will see the hardware breakpoint as a Single Step
		 *	debug event and will either handle it (so BreakpointHook cannot handle it),
		 *	or it will wait indefinitely for user input before continuing (resulting in
		 *	deadlock). For this reason, BreakpointHook will throw an exception if the
		 *	process is being debugged.
		 */

		if (!Debugger.IsAttached && k32.GetExportByName("WriteFile") is NativeExport writeFileExport)
		{
			delegate* unmanaged[Stdcall]<nint, byte*, int, int*, nint, BOOL> hookFn = &WriteFile;

			//Hardware breakpoints are set per-thread. Usually use the "Main thread"
			//which should be the oldest thread in the process.
			var firstThread = currentProc.Threads.Cast<ProcessThread>().MinBy(t => t.StartTime);

			if (writeFileExport.Hook(hookFn, firstThread, installAfterCreate: false) is INativeHook hook)
			{
				WriteFileHook = hook;
				WriteFile_original =
					(delegate* unmanaged[Stdcall]<nint, byte*, int, int*, nint, BOOL>)
				hook.OriginalFunction;

				hook.InstallHook();
			}
		}

		#endregion
		#endregion

		return 0x1337;
	}

	private static void RunForm(EventWaitHandle waitHandle, string title, string label, Image image)
	{
		HookViewer = new Form1
		{
			Text = new string(title)
		};
		HookViewer.label1.Text = label;
		HookViewer.pictureBox1.Image = image;
		HookViewer.FormClosing += HookViewer_FormClosing;
		waitHandle.Set();
		Application.EnableVisualStyles();
		Application.Run(HookViewer);
	}

	private static void HookViewer_FormClosing(object? sender, FormClosingEventArgs e)
	{
		//Disposing of the hooks will restore all original
		//executable code and free any memory allocated.
		WriteFileHook?.Dispose();
		ReadFileHook?.Dispose();
		CreateFileWHook?.Dispose();
		CloseHandleHook?.Dispose();
	}

	static Form1? HookViewer;
	static INativeHook? WriteFileHook;
	static INativeHook? ReadFileHook;
	static INativeHook? CreateFileWHook;
	static INativeHook? CloseHandleHook;
	static delegate* unmanaged[Stdcall]<nint, byte*, int, int*, nint, BOOL> WriteFile_original;
	static delegate* unmanaged[Stdcall]<nint, FileAccess, FileShare, nint, FileMode, FileAttributes, nint, nint> CreateFileW_original;
	static ReadFileDelegate? ReadFile_original;
	static delegate* unmanaged[Stdcall]<nint, BOOL> CloseHandle_original;

	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	delegate bool ReadFileDelegate(nint hFile, byte* lpBuffer, int nNumberOfBytesToWrite, ref int lpNumberOfBytesWritten, nint lpOverlapped);

	//Stdcall is the default export calling convention on x86 platforms. x64 only supports
	//fastcall, so all calling conventions map to fastcall when compiled for x64.
	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	static nint CreateFileW(
		nint lpFileName,
		FileAccess dwDesiredAccess,
		FileShare dwShareMode,
		nint lpSecurityAttributes,
		FileMode dwCreationDisposition,
		FileAttributes dwFlagsAndAttributes,
		IntPtr hTemplateFile)
	{
		var result
			= CreateFileW_original(
				lpFileName,
				dwDesiredAccess,
				dwShareMode,
				lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes,
				hTemplateFile);

		if (lpFileName != 0)
		{
			var fileName = new string(MemoryMarshal.CreateReadOnlySpanFromNullTerminated((char*)lpFileName));
			if (fileName is not null)
				LogFunction(
					$"Mode = {dwCreationDisposition}; " +
					$"Access = {dwDesiredAccess}; " +
					$"Share = {dwShareMode}; " +
					$"Flags = {dwFlagsAndAttributes}; " +
					$"File = {fileName}");
		}

		return result;
	}

	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	static BOOL CloseHandle(nint hHandle)
	{
		if (GetFilePathFromHandle(hHandle) is string fileName)
			LogFunction(fileName);

		return CloseHandle_original(hHandle);
	}

	static bool ReadFile(
		nint hFile,
		byte* lpBuffer,
		int nNumberOfBytesToRead,
		ref int lpNumberOfBytesRead,
		nint lpOverlapped)
	{
		var result = ReadFile_original!(hFile, lpBuffer, nNumberOfBytesToRead, ref lpNumberOfBytesRead, lpOverlapped);

		if (GetFilePathFromHandle(hFile) is string fileName)
			LogFunction($"Read {lpNumberOfBytesRead} of {nNumberOfBytesToRead} bytes from {fileName}");

		return result;
	}

	[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
	static BOOL WriteFile(
		nint hFile,
		byte* lpBuffer,
		int nNumberOfBytesToWrite,
		int* NumberOfBytesWritten,
		nint lpOverlapped)
	{
		//Peek at the bytes to be written
		var bytesToWrite = new Span<byte>(lpBuffer, nNumberOfBytesToWrite);

		//Write different data
		var replacementBytes = Encoding.ASCII.GetBytes("WriteFile was intercepted and modified!");

		BOOL result;
		//Call the real WriteFile function.
		fixed (byte* b = replacementBytes)
		{
			result = WriteFile_original(hFile, b, replacementBytes.Length, NumberOfBytesWritten, lpOverlapped);
		}

		if (GetFilePathFromHandle(hFile) is string fileName)
			LogFunction($"Wrote {*NumberOfBytesWritten} of {nNumberOfBytesToWrite} bytes to {fileName}");

		if (result != 0)
		{
			//Lie to the caller about the number of bytes written
			*NumberOfBytesWritten = nNumberOfBytesToWrite;
		}

		return result;
	}

	private static void LogFunction(string logMessage, [CallerMemberName] string functionName = "")
	{
		try
		{
			var timeStamp = DateTime.Now.ToString("yyyy/MM/dd HH\\:mm\\:ss.ff");

			NativeMethods.OutputDebugString($"{timeStamp} - {functionName} - {logMessage}");
			HookViewer?.LogFunction(timeStamp, functionName, logMessage);
		}
		catch { }
	}

	private static string? GetFilePathFromHandle(nint handle)
	{
		try
		{
			//Get the filename being written to
			var sz = GetFinalPathNameByHandleW(handle, null, 0, 0);
			if (sz == 0) return null;
			Span<char> buff = new char[sz];
			fixed (char* c = buff)
				sz = GetFinalPathNameByHandleW(handle, c, buff.Length, 0);

			return new string(buff.Slice(0, sz));
		}
		catch { return null; }
	}
}