using System.ComponentModel;

namespace InjectDotnet.NativeHelper.Native;

public enum ContextFlags : uint
{
	CONTEXT_i386 = 0x10000,
	CONTEXT_i486 = 0x10000,   //  same as i386
	CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
	CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
	CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
	CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
	CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
	CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
	CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
	CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
}

#if X64
/// <summary>
/// 64-bit thread context.
/// </summary>
/// <remarks>
/// For <see cref="NativeMethods.GetThreadContext(System.IntPtr, Context*)"/> and
/// <see cref="NativeMethods.SetThreadContext(System.IntPtr, Context*)"/> to succeed,
/// <see cref="Context"/> must be allocated on a 16-byte boundary. The best way to do
/// this is to allocate unmanaged memory in a new page and cast it to <see cref="Context"/>
/// </remarks>
[StructLayout(LayoutKind.Sequential, Pack = 16)]
public struct Context
{
	/// <summary>
	/// Get the thread's context.
	/// </summary>
	/// <param name="threadHandle">A handle to the thread whose context is to be retrieved. The handle must have <see cref="ThreadRights.THREAD_GET_CONTEXT"/> access to the thread.</param>
	/// <param name="flags">A value indicating which portions of the Context structure should be retrieved</param>
	/// <returns>The thread's context</returns>
	/// <exception cref="Win32Exception">If failed to get the thread context</exception>
	public unsafe static Context* GetThreadContext(nint threadHandle, ContextFlags flags = ContextFlags.CONTEXT_ALL)
	{
		//Context must be on a 16-byte boundary.
		var buff = new byte[sizeof(Context) + 8];
		fixed (byte* b = buff)
		{
			var pContext = (Context*)(b + ((int)b & 8));
			pContext->ContextFlags = ContextFlags.CONTEXT_ALL;

			if (!NativeMethods.GetThreadContext(threadHandle, pContext))
				throw new Win32Exception($"{nameof(NativeMethods.GetThreadContext)} failed.");
			return pContext;
		}
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
	public uint EFlags;            /* 044 */

	/* Debug */
	public DebugRegisters Dr;             /* 070 */

	/* Integer */
	public ulong Rax;             /* 078 */
	public ulong Rcx;             /* 080 */
	public ulong Rdx;             /* 088 */
	public ulong Rbx;             /* 090 */
	public ulong Rsp;             /* 098 */
	public ulong Rbp;             /* 0a0 */
	public ulong Rsi;             /* 0a8 */
	public ulong Rdi;             /* 0b0 */
	public ulong R8;              /* 0b8 */
	public ulong R9;              /* 0c0 */
	public ulong R10;             /* 0c8 */
	public ulong R11;             /* 0d0 */
	public ulong R12;             /* 0d8 */
	public ulong R13;             /* 0e0 */
	public ulong R14;             /* 0e8 */
	public ulong R15;             /* 0f0 */

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
	public override string ToString() => $"0x{High:X}{Low:X}";
}
#elif X86
/// <summary>
/// 32-bit thread context
/// </summary>
unsafe public struct Context
{
	/// <summary>
	/// Get the thread's context.
	/// </summary>
	/// <param name="threadHandle">A handle to the thread whose context is to be retrieved. The handle must have <see cref="ThreadRights.THREAD_GET_CONTEXT"/> access to the thread.</param>
	/// <param name="flags">A value indicating which portions of the Context structure should be retrieved</param>
	/// <returns>The thread's context</returns>
	/// <exception cref="Win32Exception">If failed to get the thread context</exception>
	public unsafe static Context* GetThreadContext(nint threadHandle, ContextFlags flags = ContextFlags.CONTEXT_ALL)
	{
		//Context must be on a 16-byte boundary.
		var buff = new byte[sizeof(Context) + 8];
		fixed (byte* b = buff)
		{
			var pContext = (Context*)(b + ((int)b & 8));
			pContext->ContextFlags = ContextFlags.CONTEXT_ALL;

			if (!NativeMethods.GetThreadContext(threadHandle, pContext))
				throw new Win32Exception($"{nameof(NativeMethods.GetThreadContext)} failed.");
			return pContext;
		}
	}

	public const int MAXIMUM_SUPPORTED_EXTENSION = 512;
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
	public uint Edi;
	public uint Esi;
	public uint Ebx;
	public uint Edx;
	public uint Ecx;
	public uint Eax;

	/* These are selected by CONTEXT_CONTROL */
	public uint Ebp;
	public nint InstructionPointer;
	public uint SegCs;
	public uint EFlags;
	public uint Esp;
	public uint SegSs;
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