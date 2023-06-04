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

using System.Runtime.InteropServices;

namespace InjectDotnet.NativeHelper.Minhook;

internal interface IHde
{
	byte Opcode { get; }
	byte Opcode2 { get; }
	byte Length { get; }
	byte ModRm { get; }
	byte ModRm_Reg { get; }
	Imm Imm { get; }
	Disp Disp { get; }
	uint Flags { get; }
	bool IsError { get; }
}

[StructLayout(LayoutKind.Explicit)]
internal struct Imm
{
	[FieldOffset(0)] public byte imm8;
	[FieldOffset(0)] public ushort imm16;
	[FieldOffset(0)] public uint imm32;
	[FieldOffset(0)] public ulong imm64;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Disp
{
	[FieldOffset(0)] public byte disp8;
	[FieldOffset(0)] public ushort disp16;
	[FieldOffset(0)] public uint disp32;
}
