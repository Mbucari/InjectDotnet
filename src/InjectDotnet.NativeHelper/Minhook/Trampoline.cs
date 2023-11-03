/*
*  MinHook - The Minimalistic API Hooking Library for x64/x86
*  Copyright (C) 2009-2017 Tsuda Kageyu.
*  All rights reserved.
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*
*   1. Redistributions of source code must retain the above copyright
*      notice, this list of conditions and the following disclaimer.
*   2. Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
*  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
*  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
*  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
*  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
*  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
*  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
*  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
*  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

using System;
using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper.Minhook;

public unsafe class Trampoline
{
#if X64
	private static readonly int TRAMPOLINE_MAX_SIZE = IntPtr.Size * 8 - sizeof(JMP_ABS);
#elif X86
	private static readonly int TRAMPOLINE_MAX_SIZE = IntPtr.Size * 8;
#endif

	/// <summary>
	/// [In] Address of the target function.
	/// </summary>
	public nint TargetAddress { get; private init; }
	/// <summary>
	/// [In] Buffer address for the trampoline and relay function.
	/// </summary>
	public nint TrampolineAddress { get; private init; }
	/// <summary>
	/// [Out] Number of the instruction boundaries.
	/// </summary>
	public uint NumIPs { get; private set; }
	/// <summary>
	/// [Out] Instruction boundaries of the target function.
	/// </summary>
	public byte[] OldIPs { get; } = new byte[8];
	/// <summary>
	/// [Out] Instruction boundaries of the trampoline function.
	/// </summary>
	public byte[] NewIPs { get; } = new byte[8];

	/// <summary>
	/// Create a trampoline for a native function
	/// </summary>
	/// <param name="hTargetFunc">Entry point of the target function to hook</param>
	/// <param name="newStart">Pointer to an an E/R/W region of memory to write the trampoline</param>
	/// <returns>A valid <see cref="Trampoline"/> if successful</returns>
	public static Trampoline? Create(nint hTargetFunc, nint newStart)
	{
		var trampoline = new Trampoline
		{
			TargetAddress = hTargetFunc,
			TrampolineAddress = newStart
		};

		return CreateTrampolineFunction(trampoline) ? trampoline : null;
	}

	private static bool CreateTrampolineFunction(Trampoline ct)
	{
		byte oldPos = 0;
		byte newPos = 0;
		nint jmpDest = 0;     // Destination address of an internal jump.
		bool finished = false; // Is the function completed?
							   //#if defined(_M_X64) || defined(__x86_64__)
		byte[] instBuf = new byte[16];

		ct.NumIPs = 0;
		do
		{
			IHde hs;
			uint copySize;
			void* pCopySrc;
			nint pOldInst = ct.TargetAddress + oldPos;
			nint pNewInst = ct.TrampolineAddress + newPos;
#if X64
			Hde64s hs64;
			copySize = Hde64s.Hde64_disasm((byte*)pOldInst, &hs64);
			hs = hs64;
#elif X86
			Hde32s hs32;
			copySize = Hde32s.Hde32_disasm((byte*)pOldInst, &hs32);
			hs = hs32;
#endif

			if (hs.IsError)
				return false;

			pCopySrc = (void*)pOldInst;
			if (oldPos >= sizeof(JMP_REL))
			{
				// The trampoline function is long enough.
				// Complete the function with the jump to the target function.
#if X64
				var jmp = new JMP_ABS(pOldInst);
				pCopySrc = &jmp;
				copySize = (uint)sizeof(JMP_ABS);
#elif X86

				var jmp = new JMP_REL(pOldInst, pNewInst);
				pCopySrc = &jmp;
				copySize = (uint)sizeof(JMP_REL);
#endif
				finished = true;
			}
#if X64
			else if ((hs.ModRm & 0xC7) == 0x05)
			{
				// Instructions using RIP relative addressing. (ModR/M = 00???101B)

				// Modify the RIP relative address.
				uint* pRelAddr;

				fixed (byte* pinstBuf = instBuf)
				{
					Buffer.MemoryCopy((void*)pOldInst, pinstBuf, copySize, copySize);

					pCopySrc = pinstBuf;

					// Relative address is stored at (instruction length - immediate value length - 4).
					pRelAddr = (uint*)(pinstBuf + hs.Length - ((hs.Flags & 0x3C) >> 2) - 4);
					*pRelAddr
						= (uint)(pOldInst + hs.Length + (int)hs.Disp.disp32 - (pNewInst + hs.Length));
				}
				// Complete the function if JMP (FF /4).
				if (hs.Opcode == 0xFF && hs.ModRm_Reg == 4)
					finished = true;
			}
#endif
			else if (hs.Opcode == 0xE8)
			{
				// Direct relative CALL
				nint dest = pOldInst + hs.Length + (int)hs.Imm.imm32;
#if X64
				var call = new CALL_ABS
				{
					opcode0 = 0xFF,
					opcode1 = 0x15,
					dummy0 = 0x00000002,
					dummy1 = 0xEB,
					dummy2 = 0x08,
					address = (ulong)dest
				};
				pCopySrc = &call;
				copySize = (uint)sizeof(CALL_ABS);

#elif X86
				var call = new JMP_REL(dest, pNewInst)
				{
					opcode = 0xE8 //Call
				};

				pCopySrc = &call;
				copySize = (uint)sizeof(JMP_REL);

#endif
			}
			else if ((hs.Opcode & 0xFD) == 0xE9)
			{
				// Direct relative JMP (EB or E9)
				nint dest = pOldInst + hs.Length;

				if (hs.Opcode == 0xEB) // isShort jmp
					dest += (sbyte)hs.Imm.imm8;
				else
					dest += (int)hs.Imm.imm32;

				// Simply copy an internal jump.
				if (ct.TargetAddress <= dest
					&& dest < ct.TargetAddress + sizeof(JMP_REL))
				{
					if (jmpDest < dest)
						jmpDest = dest;
				}
				else
				{
#if X64
					var jmp = new JMP_ABS(dest);
					pCopySrc = &jmp;
					copySize = (uint)sizeof(JMP_ABS);
#elif X86

					var jmp = new JMP_REL(dest, pNewInst);
					pCopySrc = &jmp;
					copySize = (uint)sizeof(JMP_REL);
#endif
					// Exit the function if it is not in the branch.
					finished = pOldInst >= jmpDest;
				}

			}
			else if ((hs.Opcode & 0xF0) == 0x70
					|| (hs.Opcode & 0xFC) == 0xE0
					|| (hs.Opcode2 & 0xF0) == 0x80)
			{
				// Direct relative Jcc
				nint dest = pOldInst + hs.Length;

				if ((hs.Opcode & 0xF0) == 0x70      // Jcc
					|| (hs.Opcode & 0xFC) == 0xE0)  // LOOPNZ/LOOPZ/LOOP/JECXZ
					dest += (sbyte)hs.Imm.imm8;
				else
					dest += (int)hs.Imm.imm32;

				// Simply copy an internal jump.
				if (ct.TargetAddress <= dest
					&& dest < ct.TargetAddress + sizeof(JMP_REL))
				{
					if (jmpDest < dest)
						jmpDest = dest;
				}
				else if ((hs.Opcode & 0xFC) == 0xE0)
				{
					// LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
					return false;
				}
				else
				{
					byte cond = (byte)((hs.Opcode != 0x0F ? hs.Opcode : hs.Opcode2) & 0x0F);

#if X64
					var jcc = new JCC_ABS
					{
						opcode = (byte)(0x71 ^ cond),
						dummy0 = 0xE,
						dummy1 = 0xFF,
						dummy2 = 0x25,
						address = (ulong)dest
					};
					pCopySrc = &jcc;
					copySize = (uint)sizeof(JCC_ABS);
#elif X86
					var jcc = new JCC_REL
					{
						opcode0 = 0xF,
						opcode1 = (byte)(0x80 | cond),
						operand = (uint)(dest - (pNewInst + sizeof(JCC_REL)))
					};
					pCopySrc = &jcc;
					copySize = (uint)sizeof(JCC_REL);
#endif
				}
			}
			else if ((hs.Opcode & 0xFE) == 0xC2)
			{
				// RET (C2 or C3)

				// Complete the function if not in a branch.
				finished = pOldInst >= jmpDest;
			}

			// Can't alter the instruction length in a branch.
			if (pOldInst < jmpDest && copySize != hs.Length)
				return false;

			// Trampoline function is too large.
			if (newPos + copySize > TRAMPOLINE_MAX_SIZE)
				return false;

			// Trampoline function has too many instructions.
			if (ct.NumIPs >= ct.OldIPs.Length)
				return false;

			ct.OldIPs[ct.NumIPs] = oldPos;
			ct.NewIPs[ct.NumIPs] = newPos;
			ct.NumIPs++;

			Buffer.MemoryCopy(pCopySrc, (void*)(ct.TrampolineAddress + newPos), copySize, copySize);

			newPos += (byte)copySize;
			oldPos += hs.Length;
		}
		while (!finished);

		return oldPos >= sizeof(JMP_REL);
	}
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct JMP_REL
{
	public byte opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
	public readonly uint operand;     // Relative destination address
	/// <param name="address">Address to jump to</param>
	/// <param name="jmpIP">IP of this jmp instruction for x86, 0 for x64</param>
	public JMP_REL(nint address, nint jmpIP)
	{
		opcode = 0xE9;
		operand = (uint)(address - jmpIP - sizeof(byte) - sizeof(uint));
	}
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal readonly struct JMP_ABS
{
	/// <summary>
	/// FF25 00000000: JMP [+6]
	/// </summary>
	private readonly ushort opcodes = 0x25FF;
	/// <summary>
	/// x64: RIP Offset to <see cref="address"/>
	/// <br/>
	/// x86: Location of <see cref="address"/>
	/// </summary>
	private readonly uint dummy;
	/// <summary>
	/// Absolute destination address
	/// </summary>
	public readonly nint address;

	/// <param name="address">Address to jump to</param>
	/// <param name="jmpIP">IP of this jmp instruction for x86, 0 for x64</param>
	public JMP_ABS(nint address, uint jmpIP = 0)
	{
		this.address = address;
		dummy = jmpIP == 0 ? 0 : jmpIP + sizeof(ushort) + sizeof(uint);
	}
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct CALL_ABS
{
	public byte opcode0;     // FF15 00000002: CALL [+6]
	public byte opcode1;
	public uint dummy0;
	public byte dummy1;      // EB 08:         JMP +10
	public byte dummy2;
	public ulong address;     // Absolute destination address
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct JCC_REL
{
	public byte opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
	public byte opcode1;
	public uint operand;     // Relative destination address
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct JCC_ABS
{
	public byte opcode;      // 7* 0E:         J** +16
	public byte dummy0;
	public byte dummy1;      // FF25 00000000: JMP [+6]
	public byte dummy2;
	public uint dummy3;
	public ulong address;     // Absolute destination address
}
