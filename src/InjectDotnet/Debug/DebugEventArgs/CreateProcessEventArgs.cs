using InjectDotnet.Native;
using Microsoft.Win32.SafeHandles;

namespace InjectDotnet.Debug;

/// <summary>
/// Provides process-creation information for the <see cref="Debugger.CreateProcess"/> event.
/// </summary>
public class CreateProcessEventArgs : ContinuableDebuggerEventArgs
{
	/// <summary>
	/// A handle to the process's image file. If this member is <see cref="null"/>,
	/// the handle is not valid. Otherwise, debugger can use the member to read
	/// from and write to the image file. <br/>
	/// When the debugger is finished with this file, it should close the
	/// handle using the CloseHandle function.
	/// </summary>
	public SafeFileHandle File { get; }
	/// <summary>
	/// A handle to the process. If this member is <see cref="null"/>, the handle
	/// is not valid. Otherwise, the debugger can use the member to read from and
	/// write to the process's memory.
	/// </summary>
	public nint ProcessHandle { get; }
	/// <summary>
	/// A handle to the initial thread of the process identified by the
	/// <see cref="ProcessHandle"/> member. If hThread param is <see cref="null"/>,
	/// the handle is not valid. Otherwise, the debugger has THREAD_GET_CONTEXT,
	/// THREAD_SET_CONTEXT, and THREAD_SUSPEND_RESUME access to the thread, allowing
	/// the debugger to read from and write to the registers of the thread and to
	/// control execution of the thread.
	/// </summary>
	public nint ThreadHandle { get; }
	/// <summary>
	/// The base address of the executable image that the process is running.
	/// </summary>
	public nint BaseOfImage { get; }
	/// <summary>
	/// The offset to the debugging information in the file identified by the <see cref="File"/>.
	/// </summary>
	public uint DebugInfoFileOffset { get; }
	/// <summary>
	/// The size of the debugging information in the file, in bytes. If this value is zero, there is no debugging information.
	/// </summary>
	public uint DebugInfoSize { get; }
	/// <summary>
	/// A pointer to a block of data. At offset 0x2C into this block is another
	/// pointer, called ThreadLocalStoragePointer, that points to an array of
	/// per-module thread local storage blocks. This gives a debugger access to
	/// per-thread data in the threads of the process being debugged using the same
	/// algorithms that a compiler would use.
	/// </summary>
	public nint ThreadLocalBase { get; }
	/// <summary>
	/// A pointer to the starting address of the thread. This value may only be an
	/// approximation of the thread's starting address, because any application
	/// with appropriate access to the thread can change the thread's context by
	/// using the SetThreadContext function.
	/// </summary>
	public nint StartAddress { get; }
	/// <summary>
	/// A pointer to the file name associated with the <see cref="File"/>.
	/// </summary>
	/// <remarks>
	/// This parameter may be <see cref="null"/>, or it may contain the address of a
	/// string pointer in the address space of the process being debugged. That
	/// address may, in turn, either be <see cref="null"/> or point to the actual
	/// filename. <br></br>
	/// This member is strictly optional. Debuggers must be prepared to
	/// handle the null case. Specifically, the system will never provide an image
	/// name for a create process event, and it will not likely pass an image name
	/// for the first DLL event. The system will also never provide this
	/// information in the case of debugging events that originate from a call to
	/// the DebugActiveProcess function.
	/// </remarks>
	public string? ImageName { get; }

	internal CreateProcessEventArgs(IMemoryReader memoryReader, DebugEvent debugEvent)
		: base(debugEvent)
	{
		File = new(debugEvent.u.CreateProcess.hFile, true);
		ProcessHandle = debugEvent.u.CreateProcess.hProcess;
		ThreadHandle = debugEvent.u.CreateProcess.hThread;
		BaseOfImage = debugEvent.u.CreateProcess.lpBaseOfImage;
		DebugInfoFileOffset = debugEvent.u.CreateProcess.dwDebugInfoFileOffset;
		DebugInfoSize = debugEvent.u.CreateProcess.nDebugInfoSize;
		ThreadLocalBase = debugEvent.u.CreateProcess.lpThreadLocalBase;
		StartAddress = debugEvent.u.CreateProcess.lpStartAddress;
		ImageName = debugEvent.u.CreateProcess.ReadImageNameFromTarget(memoryReader);
	}
	protected override void Dispose(bool disposing)
	{
		base.Dispose(disposing);
		File.Dispose();
	}
}
