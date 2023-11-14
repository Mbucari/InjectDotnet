using InjectDotnet.Native;
using Microsoft.Win32.SafeHandles;

namespace InjectDotnet.Debug;

/// <summary>
/// Provides information for the <see cref="Debugger.LoadDll"/> event about a
/// dynamic-link library (DLL) that has just been loaded.
/// </summary>
public class LoadDllEventArgs : ContinuableDebuggerEventArgs
{
	/// <summary>
	/// The file name associated with <see cref="File"/>.
	/// </summary>
	/// <remarks>
	/// This member may be <see cref="null"/>, or it may contain the address of a
	/// string pointer in the address space of the process being debugged. That
	/// address may, in turn, either be <see cref="null"/> or point to the actual
	/// filename. This member is strictly optional. Debuggers must be prepared to
	/// handle the null case. Specifically, the system will never provide an image
	/// name for a create process event, and it will not likely pass an image name
	/// for the first DLL event. The system will also never provide this
	/// information in the case of debugging events that originate from a call to
	/// the DebugActiveProcess function.
	/// </remarks>
	public string? ImageName { get; }
	/// <summary>
	/// The name of the Module. Subject to the same limitations as <see cref="ImageName"/>
	/// </summary>
	public string ModuleName { get; }
	/// <summary>
	/// A pointer to the base address of the DLL in the address space of the
	/// process loading the DLL.
	/// </summary>
	public nint BaseOfDll { get; }
	/// <summary>
	/// The size of the debugging information in the file, in bytes. If thi
	/// s member is zero, there is no debugging information.
	/// </summary>
	public uint DebugInfoSize { get; }
	/// <summary>
	/// The offset to the debugging information in the file identified by the
	/// <see cref="File"/> member, in bytes. The system expects the debugging
	/// information to be in CodeView 4.0 format. This format is currently a
	/// derivative of Common Object File Format (COFF).
	/// </summary>
	public uint DebugInfoFileOffset { get; }

	/// <summary>
	/// A handle to the loaded DLL. If this member is <see cref="null"/>, the
	/// handle is not valid. Otherwise, the member is opened for reading and
	/// read-sharing in the context of the debugger. <br/>
	/// When the debugger is finished with this file, it should close the
	/// handle using the CloseHandle function.
	/// </summary>
	public SafeFileHandle File { get; }

	internal LoadDllEventArgs(IMemoryReader memoryReader, DebugEvent debugEvent)
		: base(debugEvent)
	{
		BaseOfDll = debugEvent.u.LoadDll.lpBaseOfDll;
		DebugInfoSize = debugEvent.u.LoadDll.nDebugInfoSize;
		DebugInfoFileOffset = debugEvent.u.LoadDll.dwDebugInfoFileOffset;
		File = new(debugEvent.u.LoadDll.hFile, false);
		ImageName = debugEvent.u.LoadDll.ReadImageNameFromTarget(memoryReader);
		ModuleName = ImageName is null ? "unknown" : System.IO.Path.GetFileName(ImageName);
	}

	public override string? ToString() => ModuleName;

	protected override void Dispose(bool disposing)
	{
		base.Dispose(disposing);
		File.Dispose();
	}
}
