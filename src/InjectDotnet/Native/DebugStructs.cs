using System;
using System.Runtime.InteropServices;

namespace InjectDotnet.Native;

/// <summary>
/// Native debug event Codes that are returned through NativeStop event
/// </summary>
public enum DebugEventCode
{
	None = 0,
	EXCEPTION_DEBUG_EVENT = 1,
	CREATE_THREAD_DEBUG_EVENT = 2,
	CREATE_PROCESS_DEBUG_EVENT = 3,
	EXIT_THREAD_DEBUG_EVENT = 4,
	EXIT_PROCESS_DEBUG_EVENT = 5,
	LOAD_DLL_DEBUG_EVENT = 6,
	UNLOAD_DLL_DEBUG_EVENT = 7,
	OUTPUT_DEBUG_STRING_EVENT = 8,
	RIP_EVENT = 9,
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct DebugEvent
{
	public readonly DebugEventCode DebugEventCode;
	public readonly int ProcessId;
	public readonly int ThreadId;
	public readonly DebugEventUnion u;
}

[StructLayout(LayoutKind.Explicit)]
public struct DebugEventUnion
{
	[FieldOffset(0)]
	public CREATE_PROCESS_DEBUG_INFO CreateProcess;

	[FieldOffset(0)]
	public EXCEPTION_DEBUG_INFO Exception;

	[FieldOffset(0)]
	public CREATE_THREAD_DEBUG_INFO CreateThread;

	[FieldOffset(0)]
	public EXIT_THREAD_DEBUG_INFO ExitThread;

	[FieldOffset(0)]
	public EXIT_PROCESS_DEBUG_INFO ExitProcess;

	[FieldOffset(0)]
	public LOAD_DLL_DEBUG_INFO LoadDll;

	[FieldOffset(0)]
	public UNLOAD_DLL_DEBUG_INFO UnloadDll;

	[FieldOffset(0)]
	public OUTPUT_DEBUG_STRING_INFO OutputDebugString;

	[FieldOffset(0)]
	public RIP_INFO Rip;
}

public interface IImageName
{
	public nint ImageName { get; }
	public bool Unicode { get; }
}


#region RIP_INFO

[StructLayout(LayoutKind.Sequential)]
public readonly struct RIP_INFO
{
	public readonly uint dwError;
	public readonly RipErrorType Type;
}
public enum RipErrorType : uint
{
	/// <summary>
	/// Indicates that only dwError was set. 
	/// </summary>
	None,
	/// <summary>
	/// Indicates that invalid data was passed to the function that failed. This caused the application to fail. 
	/// </summary>
	SLE_ERROR,
	/// <summary>
	/// Indicates that invalid data was passed to the function, but the error probably will not cause the application to fail. 
	/// </summary>
	SLE_MINORERROR,
	/// <summary>
	/// Indicates that potentially invalid data was passed to the function, but the function completed processing. 
	/// </summary>
	SLE_WARNING
}

#endregion
#region LOAD_DLL_DEBUG_INFO

[StructLayout(LayoutKind.Sequential)]
public readonly struct LOAD_DLL_DEBUG_INFO : IImageName
{
	public readonly nint hFile;
	public readonly nint lpBaseOfDll;
	public readonly uint dwDebugInfoFileOffset;
	public readonly uint nDebugInfoSize;
	readonly nint lpImageName;
	readonly ushort fUnicode;

	public nint ImageName => lpImageName;
	public bool Unicode => fUnicode != 0;
}

#endregion
#region UNLOAD_DLL_DEBUG_INFO

[StructLayout(LayoutKind.Sequential)]
public readonly struct UNLOAD_DLL_DEBUG_INFO
{
	public readonly nint lpBaseOfDll;
}

#endregion
#region CREATE_THREAD_DEBUG_INFO

[StructLayout(LayoutKind.Sequential)]
public readonly struct CREATE_THREAD_DEBUG_INFO
{
	public readonly nint hThread;
	public readonly nint lpThreadLocalBase;
	public readonly nint lpStartAddress;
}

#endregion
#region EXIT_THREAD_DEBUG_INFO

[StructLayout(LayoutKind.Sequential)]
public readonly struct EXIT_THREAD_DEBUG_INFO
{
	public readonly uint dwExitCode;
}

#endregion
#region CREATE_PROCESS_DEBUG_INFO

[StructLayout(LayoutKind.Sequential)]
public readonly struct CREATE_PROCESS_DEBUG_INFO : IImageName
{
	public readonly nint hFile;
	public readonly nint hProcess;
	public readonly nint hThread;
	public readonly nint lpBaseOfImage;
	public readonly uint dwDebugInfoFileOffset;
	public readonly uint nDebugInfoSize;
	public readonly nint lpThreadLocalBase;
	public readonly nint lpStartAddress;
	readonly nint lpImageName;
	readonly ushort fUnicode;

	public nint ImageName => lpImageName;
	public bool Unicode => fUnicode != 0;
}

#endregion
#region EXIT_PROCESS_DEBUG_INFO

[StructLayout(LayoutKind.Sequential)]
public struct EXIT_PROCESS_DEBUG_INFO
{
	public uint dwExitCode;
}

#endregion
#region OUTPUT_DEBUG_STRING_INFO

[StructLayout(LayoutKind.Sequential)]
public readonly struct OUTPUT_DEBUG_STRING_INFO
{
	public readonly nint lpDebugStringData;
	public readonly ushort fUnicode;
	public readonly ushort nDebugStringLength;
}

#endregion
#region EXCEPTION_DEBUG_INFO

/// <summary>
/// Information about an exception debug event.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct EXCEPTION_DEBUG_INFO
{
	public EXCEPTION_RECORD ExceptionRecord;
	public uint dwFirstChance;
} // end of class EXCEPTION_DEBUG_INFO

/// <summary>
/// Information about an exception
/// </summary>    
/// <remarks>This will default to the correct caller's platform</remarks>
[StructLayout(LayoutKind.Sequential)]
public readonly struct EXCEPTION_RECORD
{
	readonly ExceptionCode _ExceptionCode;
	readonly ExceptionRecordFlags _ExceptionFlags;

	/// <summary>
	/// Based off ExceptionFlags, is the exception Non-continuable?
	/// </summary>
	public bool IsNotContinuable => (ExceptionFlags & ExceptionRecordFlags.EXCEPTION_NONCONTINUABLE) != 0;

	readonly nint ExceptionRecord;

	/// <summary>
	/// Address in the debuggee that the exception occured at.
	/// </summary>
	readonly nint _ExceptionAddress;

	/// <summary>
	/// Number of parameters used in ExceptionInformation array.
	/// </summary>
	readonly nuint _NumberParameters;

	const int EXCEPTION_MAXIMUM_PARAMETERS = 15;
	// We'd like to marshal this as a ByValArray, but that's not supported yet.
	// We get an alignment error  / TypeLoadException for DebugEventUnion
	//[MarshalAs(UnmanagedType.ByValArray, SizeConst = EXCEPTION_MAXIMUM_PARAMETERS)]
	//public IntPtr [] ExceptionInformation;

	// Instead, mashal manually.
	readonly nint ExceptionInformation0;
	readonly nint ExceptionInformation1;
	readonly nint ExceptionInformation2;
	readonly nint ExceptionInformation3;
	readonly nint ExceptionInformation4;
	readonly nint ExceptionInformation5;
	readonly nint ExceptionInformation6;
	readonly nint ExceptionInformation7;
	readonly nint ExceptionInformation8;
	readonly nint ExceptionInformation9;
	readonly nint ExceptionInformation10;
	readonly nint ExceptionInformation11;
	readonly nint ExceptionInformation12;
	readonly nint ExceptionInformation13;
	readonly nint ExceptionInformation14;

	public ExceptionCode ExceptionCode => _ExceptionCode;
	public ExceptionRecordFlags ExceptionFlags => _ExceptionFlags;
	public nint ExceptionAddress => _ExceptionAddress;
	public int NumberParameters => (int)_NumberParameters;

	public bool HasInnerException => ExceptionRecord != 0;

	public nint[] ExceptionRecords => new nint[EXCEPTION_MAXIMUM_PARAMETERS]
	{
		ExceptionInformation0,
		ExceptionInformation1,
		ExceptionInformation2,
		ExceptionInformation3,
		ExceptionInformation4,
		ExceptionInformation5,
		ExceptionInformation6,
		ExceptionInformation7,
		ExceptionInformation8,
		ExceptionInformation9,
		ExceptionInformation10,
		ExceptionInformation11,
		ExceptionInformation12,
		ExceptionInformation13,
		ExceptionInformation14,
	};

	public readonly EXCEPTION_RECORD GetInnerException(IMemoryReader memoryReader)
		=> memoryReader.ReadStruct<EXCEPTION_RECORD>(ExceptionRecord);
}

/// <summary>
/// Common ExceptionRecord codes
/// </summary>
/// <remarks>Users can define their own exception codes, so the code could be any value. 
/// The OS reserves bit 28 and may clear that for its own purposes</remarks>
public enum ExceptionCode : uint
{
	None = 0x0, // included for completeness sake

	/// <summary>
	/// Raised when debuggee gets a Control-C. 
	/// </summary>
	DBG_CONTROL_C = 0x40010005,
	/// <summary>
	///  The thread tried to read from or write to a virtual address for which it does not have the appropriate access. 
	/// </summary>
	EXCEPTION_ACCESS_VIOLATION = 0xC0000005,
	/// <summary>
	///  The thread tried to read or write data that is misaligned on hardware that does not provide alignment. For example, 16-bit values must be aligned on 2-byte boundaries; 32-bit values on 4-byte boundaries, and so on. 
	/// </summary>
	EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002,
	/// <summary>
	///  A breakpoint was encountered. 
	/// </summary>
	EXCEPTION_BREAKPOINT = 0x80000003,
	/// <summary>
	///  A trace trap or other single-instruction mechanism signaled that one instruction has been executed. 
	/// </summary>
	EXCEPTION_SINGLE_STEP = 0x80000004,
	/// <summary>
	///  The thread tried to access an array element that is out of bounds and the underlying hardware supports bounds checking. 
	/// </summary>
	EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C,
	/// <summary>
	///  One of the operands in a floating-point operation is denormal. A denormal value is one that is too small to represent as a standard floating-point value. 
	/// </summary>
	EXCEPTION_FLT_DENORMAL_OPERAND = 0xC000008D,
	/// <summary>
	///  The thread tried to divide a floating-point value by a floating-point divisor of zero. 
	/// </summary>
	EXCEPTION_FLT_DIVIDE_BY_ZERO = 0xC000008E,
	/// <summary>
	///  The result of a floating-point operation cannot be represented exactly as a decimal fraction. 
	/// </summary>
	EXCEPTION_FLT_INEXACT_RESULT = 0xC000008F,
	/// <summary>
	///  This exception represents any floating-point exception not included in this list. 
	/// </summary>
	EXCEPTION_FLT_INVALID_OPERATION = 0xC0000090,
	/// <summary>
	///  The exponent of a floating-point operation is greater than the magnitude allowed by the corresponding type. 
	/// </summary>
	EXCEPTION_FLT_OVERFLOW = 0xC0000091,
	/// <summary>
	///  The stack overflowed or underflowed as the result of a floating-point operation. 
	/// </summary>
	EXCEPTION_FLT_STACK_CHECK = 0xC0000092,
	/// <summary>
	///  The exponent of a floating-point operation is less than the magnitude allowed by the corresponding type. 
	/// </summary>
	EXCEPTION_FLT_UNDERFLOW = 0xC0000093,
	/// <summary>
	///  The thread tried to divide an integer value by an integer divisor of zero. 
	/// </summary>
	EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094,
	/// <summary>
	///  The result of an integer operation caused a carry out of the most significant bit of the result. 
	/// </summary>
	EXCEPTION_INT_OVERFLOW = 0xC0000095,
	/// <summary>
	///  The thread tried to execute an instruction whose operation is not allowed in the current machine mode. 
	/// </summary>
	EXCEPTION_PRIV_INSTRUCTION = 0xC0000096,
	/// <summary>
	///  The thread tried to access a page that was not present, and the system was unable to load the page. For example, this exception might occur if a network connection is lost while running a program over the network. 
	/// </summary>
	EXCEPTION_IN_PAGE_ERROR = 0xC0000006,
	/// <summary>
	///  The thread tried to execute an invalid instruction. 
	/// </summary>
	EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D,
	/// <summary>
	///  The thread tried to continue execution after a noncontinuable exception occurred. 
	/// </summary>
	EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xC0000025,
	/// <summary>
	///  The thread used up its stack. 
	/// </summary>
	EXCEPTION_STACK_OVERFLOW = 0xC00000FD,
	/// <summary>
	///  An exception handler returned an invalid disposition to the exception dispatcher. Programmers using a high-level language such as C should never encounter this exception. 
	/// </summary>
	EXCEPTION_INVALID_DISPOSITION = 0xC0000026,
	/// <summary>
	/// The thread accessed memory allocated with the PAGE_GUARD modifier.
	/// </summary>
	EXCEPTION_GUARD_PAGE = 0x80000001,
	/// <summary>
	/// The thread used a handle to a kernel object that was invalid (probably because it had been closed.)
	/// </summary>
	EXCEPTION_INVALID_HANDLE = 0xC0000008,
	/// <summary>
	/// A wait operation on the critical section times out.
	/// </summary>
	EXCEPTION_POSSIBLE_DEADLOCK = 0xC0000194,

	CLRDBG_NOTIFICATION_EXCEPTION_CODE = 0x04242420
}

/// <summary>
/// Flags for <see cref="EXCEPTION_RECORD"/>.  Exception flags not present in this enum should be treated as reserved for system use.
/// </summary>
[Flags]
public enum ExceptionRecordFlags : uint
{
	/// <summary>
	/// No flags. 
	/// </summary>
	None = 0x0,

	/// <summary>
	/// The presence of this flag indicates that the exception is a noncontinuable
	/// exception, whereas the absence of this flag indicates that the exception is
	/// a continuable exception. Any attempt to continue execution after a
	/// noncontinuable exception causes the EXCEPTION_NONCONTINUABLE_EXCEPTION exception. 
	/// </summary>
	EXCEPTION_NONCONTINUABLE = 0x1,
}

#endregion
