using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace InjectDotnet.Native;

[Flags]
public enum Flags : uint
{
	CF = 1,
	_1 = 2,
	PF = 4,
	_2 = 8,
	AF = 0x10,
	_5 = 0x20,
	ZF = 0x40,
	SF = 0x80,
	TF = 0x100,
	IF = 0x200,
	DF = 0x400,
	OF = 0x800,
	IOPL = 0x3000,
	NT = 0x4000,
	MD = 0x8000,
	//EFlags
	RF = 0x10000,
	VM = 0x20000,
	AC = 0x40000,
	VIF = 0x80000,
	VIP = 0x100000,
	ID = 0x200000,
	Reserved = 0x3FC00000,
}

#if X64
public enum ContextFlags : uint
{
	None = 0,
	Context = 0x100000,
	ContextControl = Context | 0x1,   // SS:SP, CS:IP, FLAGS, BP
	ContextInteger = Context | 0x2,   // AX, BX, CX, DX, SI, DI
	ContextSegments = Context | 0x4,  // DS, ES, FS, GS
	ContextFloatingPoint = Context | 0x8, // 387 state
	ContextDebugRegisters = Context | 0x10,   // DB 0-3,6,7
	ContextFull = Context | ContextControl | ContextInteger | ContextFloatingPoint,
	ContextAll = Context | ContextControl | ContextInteger | ContextSegments |
						ContextFloatingPoint | ContextDebugRegisters,
}


/// <summary>
/// 64-bit thread context.
/// </summary>
/// <remarks>
/// For <see cref="NativeMethods.GetThreadContext(System.IntPtr, Context*)"/> and
/// <see cref="NativeMethods.SetThreadContext(System.IntPtr, Context)"/> to succeed,
/// <see cref="Context"/> must be allocated on a 16-byte boundary. The best way to do
/// this is to allocate unmanaged memory in a new page and cast it to <see cref="Context"/>
/// </remarks>
[StructLayout(LayoutKind.Sequential, Pack = 16)]
public class Context
{
	public static Context GetThreadContext(int threadId, ContextFlags contextFlags)
	{
		var threadHandle = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, false, threadId);
		var ctx = GetThreadContext(threadHandle, contextFlags);
		NativeMethods.CloseHandle(threadHandle);
		return ctx;
	}
	public static Context GetThreadContext(nint threadHandle, ContextFlags contextFlags)
	{
		var ctx = new Context { ContextFlags = contextFlags };
		NativeMethods.GetThreadContext(threadHandle, ctx);
		return ctx;
	}

	public ulong P1Home;          /* 000 */
	public ulong P2Home;          /* 008 */
	public ulong P3Home;          /* 010 */
	public ulong P4Home;          /* 018 */
	public ulong P5Home;          /* 020 */
	public ulong P6Home;          /* 028 */

	/* Control flags */
	public ContextFlags ContextFlags;      /* 030 */
	public uint MxCsr;             /* 034 */

	/* Segment */
	public ushort SegCs;              /* 038 */
	public ushort SegDs;              /* 03a */
	public ushort SegEs;              /* 03c */
	public ushort SegFs;              /* 03e */
	public ushort SegGs;              /* 040 */
	public ushort SegSs;              /* 042 */
	public Flags EFlags;            /* 044 */

	/* Debug */
	public DebugRegisters Dr;             /* 070 */

	/* Integer */
	public nint Rax;             /* 078 */
	public nint Rcx;             /* 080 */
	public nint Rdx;             /* 088 */
	public nint Rbx;             /* 090 */
	public nint StackPointer;    /* 098 */
	public nint Rbp;             /* 0a0 */
	public nint Rsi;             /* 0a8 */
	public nint Rdi;             /* 0b0 */
	public nint R8;              /* 0b8 */
	public nint R9;              /* 0c0 */
	public nint R10;             /* 0c8 */
	public nint R11;             /* 0d0 */
	public nint R12;             /* 0d8 */
	public nint R13;             /* 0e0 */
	public nint R14;             /* 0e8 */
	public nint R15;             /* 0f0 */

	/* Counter */
	public nint InstructionPointer;             /* 0f8 */

	public XMM_SAVE_AREA32 FPointRegisters;  /* 100 */

	public M128A VectorRegister00;/* 300 */
	public M128A VectorRegister01;
	public M128A VectorRegister02;
	public M128A VectorRegister03;
	public M128A VectorRegister04;
	public M128A VectorRegister05;
	public M128A VectorRegister06;
	public M128A VectorRegister07;
	public M128A VectorRegister08;
	public M128A VectorRegister09;
	public M128A VectorRegister10;
	public M128A VectorRegister11;
	public M128A VectorRegister12;
	public M128A VectorRegister13;
	public M128A VectorRegister14;
	public M128A VectorRegister15;
	public M128A VectorRegister16;
	public M128A VectorRegister17;
	public M128A VectorRegister18;
	public M128A VectorRegister19;
	public M128A VectorRegister20;
	public M128A VectorRegister21;
	public M128A VectorRegister22;
	public M128A VectorRegister23;
	public M128A VectorRegister24;
	public M128A VectorRegister25;

	public ulong VectorControl;        /* 4a0 */

	/* Debug control */
	public ulong DebugControl;         /* 4a8 */
	public ulong LastBranchToRip;      /* 4b0 */
	public ulong LastBranchFromRip;    /* 4b8 */
	public ulong LastExceptionToRip;   /* 4c0 */
	public ulong LastExceptionFromRip; /* 4c8 */
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public unsafe struct XMM_SAVE_AREA32
{
	public ushort ControlWord;
	public ushort StatusWord;
	public byte TagWord;
	public byte Reserved1;
	public ushort ErrorOpcode;
	public uint ErrorOffset;
	public ushort ErrorSelector;
	public ushort Reserved2;
	public uint DataOffset;
	public ushort DataSelector;
	public ushort Reserved3;
	public uint MxCsr;
	public uint MxCsr_Mask;

	public M128A FloatRegister0;
	public M128A FloatRegister1;
	public M128A FloatRegister2;
	public M128A FloatRegister3;
	public M128A FloatRegister4;
	public M128A FloatRegister5;
	public M128A FloatRegister6;
	public M128A FloatRegister7;
	public M128A Xmm00;
	public M128A Xmm01;
	public M128A Xmm02;
	public M128A Xmm03;
	public M128A Xmm04;
	public M128A Xmm05;
	public M128A Xmm06;
	public M128A Xmm07;
	public M128A Xmm08;
	public M128A Xmm09;
	public M128A Xmm10;
	public M128A Xmm11;
	public M128A Xmm12;
	public M128A Xmm13;
	public M128A Xmm14;
	public M128A Xmm15;

	private fixed byte Reserved4[96];
}

[DebuggerDisplay("{ToString(),nq}")]
[StructLayout(LayoutKind.Sequential)]
public struct M128A
{
	public ulong High;
	public long Low;
	public override string ToString() => $"0x{High:X16}{Low:X16}";
}
#elif X86

public enum ContextFlags : uint
{
	None = 0,
	Context = 0x10000,
	ContextControl = Context | 0x1, // SS:SP, CS:IP, FLAGS, BP
	ContextInteger = Context | 0x2,   // AX, BX, CX, DX, SI, DI
	ContextSegments = Context | 0x4,  // DS, ES, FS, GS
	ContextFloatingPoint = Context | 0x8, // 387 state
	ContextDebugRegisters = Context | 0x10,   // DB 0-3,6,7
	ContextExtendedRegisters = Context | 0x20,
	ContextFull = Context | ContextControl | ContextInteger | ContextSegments,
	ContextAll = Context | ContextControl | ContextInteger | ContextSegments | ContextFloatingPoint |
		ContextDebugRegisters | ContextExtendedRegisters
}

/// <summary>
/// 32-bit thread context
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public class Context
{
	public static Context GetThreadContext(int threadId, ContextFlags contextFlags)
	{
		var threadHandle = NativeMethods.OpenThread(ThreadAccess.THREAD_ALL_ACCESS, false, threadId);
		var ctx = GetThreadContext(threadHandle, contextFlags);
		NativeMethods.CloseHandle(threadHandle);
		return ctx;
	}
	public static Context GetThreadContext(nint threadHandle, ContextFlags contextFlags)
	{
		var ctx = new Context { ContextFlags = contextFlags };
		NativeMethods.GetThreadContext(threadHandle, ctx);
		return ctx;
	}

	public ContextFlags ContextFlags;

	/* These are selected by CONTEXT_DEBUG_REGISTERS */
	public DebugRegisters Dr;

	/* These are selected by CONTEXT_FLOATING_POINT */
	public FLOATING_SAVE_AREA FloatSave;

	/* These are selected by CONTEXT_SEGMENTS */
	public uint SegGs;
	public uint SegFs;
	public uint SegEs;
	public uint SegDs;

	/* These are selected by CONTEXT_INTEGER */
	public nint Edi;
	public nint Esi;
	public nint Ebx;
	public nint Edx;
	public nint Ecx;
	public nint Eax;

	/* These are selected by CONTEXT_CONTROL */
	public nint Ebp;
	public nint InstructionPointer;
	public uint SegCs;
	public Flags EFlags;
	public nint StackPointer;
	public uint SegSs;
	public X86_EXTENDED ExtendedRegisters;

}

public unsafe struct X86_EXTENDED
{
	public const int MAXIMUM_SUPPORTED_EXTENSION = 512;
	public fixed byte ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
}

public unsafe struct FLOATING_SAVE_AREA
{
	private const int SIZE_OF_80387_REGISTERS = 80;
	public uint ControlWord;
	public uint StatusWord;
	public uint TagWord;
	public uint ErrorOffset;
	public uint ErrorSelector;
	public uint DataOffset;
	public uint DataSelector;
	public fixed byte RegisterArea[SIZE_OF_80387_REGISTERS];
	public uint Cr0NpxState;
}

#endif