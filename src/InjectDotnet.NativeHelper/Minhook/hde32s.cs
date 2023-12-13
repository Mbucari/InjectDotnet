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

namespace InjectDotnet.NativeHelper.Minhook
{
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	struct Hde32s : IHde
	{
		private byte len;
		public byte p_rep;
		public byte p_lock;
		public byte p_seg;
		public byte p_66;
		public byte p_67;
		private byte opcode;
		private byte opcode2;
		private byte modrm;
		public byte modrm_mod;
		private byte modrm_reg;
		public byte modrm_rm;
		public byte sib;
		public byte sib_scale;
		public byte sib_index;
		public byte sib_base;
		private Imm imm;
		private Disp disp;
		private uint flags;

		public byte Opcode => opcode;
		public byte Length => len;
		public byte Opcode2 => opcode2;
		public Imm Imm => imm;
		public Disp Disp => disp;
		public byte ModRm => modrm;
		public byte ModRm_Reg => modrm_reg;
		public uint Flags => flags;
		public bool IsError => (flags & F_ERROR) != 0;

		unsafe public static uint Hde32_disasm(byte* code, Hde32s* hs)
		{

			fixed (byte* hde32_table = hde32_table_array)
			{
				byte x, c = 0, cflags, opcode, pref = 0;
				byte* p = code, ht = hde32_table;
				byte m_mod, m_reg, m_rm, disp_size = 0;
				bool rel32_ok_bool = false;

				for (x = 16; x != 0; x--)
					switch (c = *p++)
					{
						case 0xf3:
							hs->p_rep = c;
							pref |= PRE_F3;
							break;
						case 0xf2:
							hs->p_rep = c;
							pref |= PRE_F2;
							break;
						case 0xf0:
							hs->p_lock = c;
							pref |= PRE_LOCK;
							break;
						case 0x26:
						case 0x2e:
						case 0x36:
						case 0x3e:
						case 0x64:
						case 0x65:
							hs->p_seg = c;
							pref |= PRE_SEG;
							break;
						case 0x66:
							hs->p_66 = c;
							pref |= PRE_66;
							break;
						case 0x67:
							hs->p_67 = c;
							pref |= PRE_67;
							break;
						default:
							goto pref_done;
					}
				pref_done:

				hs->flags = (uint)pref << 23;

				if (pref == 0)
					pref |= PRE_NONE;

				if ((hs->opcode = c) == 0x0f)
				{
					hs->opcode2 = c = *p++;
					ht += DELTA_OPCODES;
				}
				else if (c >= 0xa0 && c <= 0xa3)
				{
					if ((pref & PRE_67) != 0)
						pref |= PRE_66;
					else
						pref &= unchecked((byte)~PRE_66);
				}

				opcode = c;
				cflags = ht[ht[opcode / 4] + opcode % 4];

				if (cflags == C_ERROR)
				{
					hs->flags |= F_ERROR | F_ERROR_OPCODE;
					cflags = 0;
					if ((opcode & -3) == 0x24)
						cflags++;
				}

				x = 0;
				if ((cflags & C_GROUP) != 0)
				{
					ushort t;
					t = *(ushort*)(ht + (cflags & 0x7f));
					cflags = (byte)t;
					x = (byte)(t >> 8);
				}

				if (hs->opcode2 != 0)
				{
					ht = hde32_table + DELTA_PREFIXES;
					if ((ht[ht[opcode / 4] + opcode % 4] & pref) != 0)
						hs->flags |= F_ERROR | F_ERROR_OPCODE;
				}

				if ((cflags & C_MODRM) != 0)
				{
					hs->flags |= F_MODRM;
					hs->modrm = c = *p++;
					hs->modrm_mod = m_mod = (byte)(c >> 6);
					hs->modrm_rm = m_rm = (byte)(c & 7);
					hs->modrm_reg = m_reg = (byte)((c & 0x3f) >> 3);

					if (x != 0 && (x << m_reg & 0x80) != 0)
						hs->flags |= F_ERROR | F_ERROR_OPCODE;

					if (hs->opcode2 == 0 && opcode >= 0xd9 && opcode <= 0xdf)
					{
						byte t = (byte)(opcode - 0xd9);
						if (m_mod == 3)
						{
							ht = hde32_table + DELTA_FPU_MODRM + t * 8;
							t = (byte)(ht[m_reg] << m_rm);
						}
						else
						{
							ht = hde32_table + DELTA_FPU_REG;
							t = (byte)(ht[t] << m_reg);
						}
						if ((t & 0x80) != 0)
							hs->flags |= F_ERROR | F_ERROR_OPCODE;
					}

					if ((pref & PRE_LOCK) != 0)
					{
						if (m_mod == 3)
						{
							hs->flags |= F_ERROR | F_ERROR_LOCK;
						}
						else
						{
							byte* table_end, op = (byte*)opcode;
							if (hs->opcode2 != 0)
							{
								ht = hde32_table + DELTA_OP2_LOCK_OK;
								table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
							}
							else
							{
								ht = hde32_table + DELTA_OP_LOCK_OK;
								table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
								op = unchecked((byte*)(byte)((int)op & -2));
							}
							for (; ht != table_end; ht++)
								if (*ht++ == (byte)op)
								{
									if ((*ht << m_reg & 0x80) == 0)
										goto no_lock_error;
									else
										break;
								}
							hs->flags |= F_ERROR | F_ERROR_LOCK;
						no_lock_error:
							;
						}
					}

					if (hs->opcode2 != 0)
					{
						switch (opcode)
						{
							case 0x20:
							case 0x22:
								m_mod = 3;
								if (m_reg > 4 || m_reg == 1)
									goto error_operand;
								else
									goto no_error_operand;
							case 0x21:
							case 0x23:
								m_mod = 3;
								if (m_reg == 4 || m_reg == 5)
									goto error_operand;
								else
									goto no_error_operand;
						}
					}
					else
					{
						switch (opcode)
						{
							case 0x8c:
								if (m_reg > 5)
									goto error_operand;
								else
									goto no_error_operand;
							case 0x8e:
								if (m_reg == 1 || m_reg > 5)
									goto error_operand;
								else
									goto no_error_operand;
						}
					}

					if (m_mod == 3)
					{
						byte* table_end;
						if (hs->opcode2 != 0)
						{
							ht = hde32_table + DELTA_OP2_ONLY_MEM;
							table_end = ht + hde32_table_array.Length - DELTA_OP2_ONLY_MEM;
						}
						else
						{
							ht = hde32_table + DELTA_OP_ONLY_MEM;
							table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
						}
						for (; ht != table_end; ht += 2)
							if (*ht++ == opcode)
							{
								if ((*ht++ & pref) != 0 && (*ht << m_reg & 0x80) == 0)
									goto error_operand;
								else
									break;
							}
						goto no_error_operand;
					}
					else if (hs->opcode2 != 0)
					{
						switch (opcode)
						{
							case 0x50:
							case 0xd7:
							case 0xf7:
								if ((pref & (PRE_NONE | PRE_66)) != 0)
									goto error_operand;
								break;
							case 0xd6:
								if ((pref & (PRE_F2 | PRE_F3)) != 0)
									goto error_operand;
								break;
							case 0xc5:
								goto error_operand;
						}
						goto no_error_operand;
					}
					else
						goto no_error_operand;

					error_operand:
					hs->flags |= F_ERROR | F_ERROR_OPERAND;
				no_error_operand:

					c = *p++;
					if (m_reg <= 1)
					{
						if (opcode == 0xf6)
							cflags |= C_IMM8;
						else if (opcode == 0xf7)
							cflags |= C_IMM_P66;
					}

					switch (m_mod)
					{
						case 0:
							if ((pref & PRE_67) != 0)
							{
								if (m_rm == 6)
									disp_size = 2;
							}
							else
								if (m_rm == 5)
								disp_size = 4;
							break;
						case 1:
							disp_size = 1;
							break;
						case 2:
							disp_size = 2;
							if ((pref & PRE_67) == 0)
								disp_size <<= 1;
							break;
					}

					if (m_mod != 3 && m_rm == 4 && (pref & PRE_67) == 0)
					{
						hs->flags |= F_SIB;
						p++;
						hs->sib = c;
						hs->sib_scale = (byte)(c >> 6);
						hs->sib_index = (byte)((c & 0x3f) >> 3);
						if ((hs->sib_base = (byte)(c & 7)) == 5 && (m_mod & 1) == 0)
							disp_size = 4;
					}

					p--;
					switch (disp_size)
					{
						case 1:
							hs->flags |= F_DISP8;
							hs->disp.disp8 = *p;
							break;
						case 2:
							hs->flags |= F_DISP16;
							hs->disp.disp16 = *(ushort*)p;
							break;
						case 4:
							hs->flags |= F_DISP32;
							hs->disp.disp32 = *(uint*)p;
							break;
					}
					p += disp_size;
				}
				else if ((pref & PRE_LOCK) != 0)
					hs->flags |= F_ERROR | F_ERROR_LOCK;

				if ((cflags & C_IMM_P66) != 0)
				{
					if ((cflags & C_REL32) != 0)
					{
						if ((pref & PRE_66) != 0)
						{
							hs->flags |= F_IMM16 | F_RELATIVE;
							hs->imm.imm16 = *(ushort*)p;
							p += 2;
							goto disasm_done;
						}
						rel32_ok_bool = true;
						goto rel32_ok;
					}
					if ((pref & PRE_66) != 0)
					{
						hs->flags |= F_IMM16;
						hs->imm.imm16 = *(ushort*)p;
						p += 2;
					}
					else
					{
						hs->flags |= F_IMM32;
						hs->imm.imm32 = *(uint*)p;
						p += 4;
					}
				}

				if ((cflags & C_IMM16) != 0)
				{
					if ((hs->flags & F_IMM32) != 0)
					{
						hs->flags |= F_IMM16;
						hs->disp.disp16 = *(ushort*)p;
					}
					else if ((hs->flags & F_IMM16) != 0)
					{
						hs->flags |= F_2IMM16;
						hs->disp.disp16 = *(ushort*)p;
					}
					else
					{
						hs->flags |= F_IMM16;
						hs->imm.imm16 = *(ushort*)p;
					}
					p += 2;
				}
				if ((cflags & C_IMM8) != 0)
				{
					hs->flags |= F_IMM8;
					hs->imm.imm8 = *p++;
				}

			rel32_ok:
				if (rel32_ok_bool && (cflags & C_REL32) != 0)
				{
					hs->flags |= F_IMM32 | F_RELATIVE;
					hs->imm.imm32 = *(uint*)p;
					p += 4;
				}
				else if ((cflags & C_REL8) != 0)
				{
					hs->flags |= F_IMM8 | F_RELATIVE;
					hs->imm.imm8 = *p++;
				}

			disasm_done:

				if ((hs->len = (byte)(p - code)) > 15)
				{
					hs->flags |= F_ERROR | F_ERROR_LENGTH;
					hs->len = 15;
				}

				return hs->len;
			}
		}

		#region Constants
		public const uint F_MODRM = 0x00000001;
		public const uint F_SIB = 0x00000002;
		public const uint F_IMM8 = 0x00000004;
		public const uint F_IMM16 = 0x00000008;
		public const uint F_IMM32 = 0x00000010;
		public const uint F_DISP8 = 0x00000020;
		public const uint F_DISP16 = 0x00000040;
		public const uint F_DISP32 = 0x00000080;
		public const uint F_RELATIVE = 0x00000100;
		public const uint F_2IMM16 = 0x00000800;
		public const uint F_ERROR = 0x00001000;
		public const uint F_ERROR_OPCODE = 0x00002000;
		public const uint F_ERROR_LENGTH = 0x00004000;
		public const uint F_ERROR_LOCK = 0x00008000;
		public const uint F_ERROR_OPERAND = 0x00010000;
		public const uint F_PREFIX_REPNZ = 0x01000000;
		public const uint F_PREFIX_REPX = 0x02000000;
		public const uint F_PREFIX_REP = 0x03000000;
		public const uint F_PREFIX_66 = 0x04000000;
		public const uint F_PREFIX_67 = 0x08000000;
		public const uint F_PREFIX_LOCK = 0x10000000;
		public const uint F_PREFIX_SEG = 0x20000000;
		public const uint F_PREFIX_ANY = 0x3f000000;

		public const byte PREFIX_SEGMENT_CS = 0x2e;
		public const byte PREFIX_SEGMENT_SS = 0x36;
		public const byte PREFIX_SEGMENT_DS = 0x3e;
		public const byte PREFIX_SEGMENT_ES = 0x26;
		public const byte PREFIX_SEGMENT_FS = 0x64;
		public const byte PREFIX_SEGMENT_GS = 0x65;
		public const byte PREFIX_LOCK = 0xf0;
		public const byte PREFIX_REPNZ = 0xf2;
		public const byte PREFIX_REPX = 0xf3;
		public const byte PREFIX_OPERAND_SIZE = 0x66;
		public const byte PREFIX_ADDRESS_SIZE = 0x67;
		#endregion

		#region Table
		public const byte C_NONE = 0x00;
		public const byte C_MODRM = 0x01;
		public const byte C_IMM8 = 0x02;
		public const byte C_IMM16 = 0x04;
		public const byte C_IMM_P66 = 0x10;
		public const byte C_REL8 = 0x20;
		public const byte C_REL32 = 0x40;
		public const byte C_GROUP = 0x80;
		public const byte C_ERROR = 0xff;

		public const byte PRE_ANY = 0x00;
		public const byte PRE_NONE = 0x01;
		public const byte PRE_F2 = 0x02;
		public const byte PRE_F3 = 0x04;
		public const byte PRE_66 = 0x08;
		public const byte PRE_67 = 0x10;
		public const byte PRE_LOCK = 0x20;
		public const byte PRE_SEG = 0x40;
		public const byte PRE_ALL = 0xff;

		public const byte DELTA_OPCODES = 0x4a;
		public const byte DELTA_FPU_REG = 0xf1;
		public const byte DELTA_FPU_MODRM = 0xf8;
		public const ushort DELTA_PREFIXES = 0x130;
		public const ushort DELTA_OP_LOCK_OK = 0x1a1;
		public const ushort DELTA_OP2_LOCK_OK = 0x1b9;
		public const ushort DELTA_OP_ONLY_MEM = 0x1cb;
		public const ushort DELTA_OP2_ONLY_MEM = 0x1da;

		private static readonly byte[] hde32_table_array = {
  0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,0xa8,0xa3,
  0xa8,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xac,0xaa,0xb2,0xaa,0x9f,0x9f,
  0x9f,0x9f,0xb5,0xa3,0xa3,0xa4,0xaa,0xaa,0xba,0xaa,0x96,0xaa,0xa8,0xaa,0xc3,
  0xc3,0x96,0x96,0xb7,0xae,0xd6,0xbd,0xa3,0xc5,0xa3,0xa3,0x9f,0xc3,0x9c,0xaa,
  0xaa,0xac,0xaa,0xbf,0x03,0x7f,0x11,0x7f,0x01,0x7f,0x01,0x3f,0x01,0x01,0x90,
  0x82,0x7d,0x97,0x59,0x59,0x59,0x59,0x59,0x7f,0x59,0x59,0x60,0x7d,0x7f,0x7f,
  0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x9a,0x88,0x7d,
  0x59,0x50,0x50,0x50,0x50,0x59,0x59,0x59,0x59,0x61,0x94,0x61,0x9e,0x59,0x59,
  0x85,0x59,0x92,0xa3,0x60,0x60,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,0x59,
  0x59,0x59,0x9f,0x01,0x03,0x01,0x04,0x03,0xd5,0x03,0xcc,0x01,0xbc,0x03,0xf0,
  0x10,0x10,0x10,0x10,0x50,0x50,0x50,0x50,0x14,0x20,0x20,0x20,0x20,0x01,0x01,
  0x01,0x01,0xc4,0x02,0x10,0x00,0x00,0x00,0x00,0x01,0x01,0xc0,0xc2,0x10,0x11,
  0x02,0x03,0x11,0x03,0x03,0x04,0x00,0x00,0x14,0x00,0x02,0x00,0x00,0xc6,0xc8,
  0x02,0x02,0x02,0x02,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0xff,0xca,
  0x01,0x01,0x01,0x00,0x06,0x00,0x04,0x00,0xc0,0xc2,0x01,0x01,0x03,0x01,0xff,
  0xff,0x01,0x00,0x03,0xc4,0xc4,0xc6,0x03,0x01,0x01,0x01,0xff,0x03,0x03,0x03,
  0xc8,0x40,0x00,0x0a,0x00,0x04,0x00,0x00,0x00,0x00,0x7f,0x00,0x33,0x01,0x00,
  0x00,0x00,0x00,0x00,0x00,0xff,0xbf,0xff,0xff,0x00,0x00,0x00,0x00,0x07,0x00,
  0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0xff,0xff,0x00,0x00,0x00,0xbf,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  0x7f,0x00,0x00,0xff,0x4a,0x4a,0x4a,0x4a,0x4b,0x52,0x4a,0x4a,0x4a,0x4a,0x4f,
  0x4c,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x55,0x45,0x40,0x4a,0x4a,0x4a,
  0x45,0x59,0x4d,0x46,0x4a,0x5d,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,0x4a,
  0x4a,0x4a,0x4a,0x4a,0x4a,0x61,0x63,0x67,0x4e,0x4a,0x4a,0x6b,0x6d,0x4a,0x4a,
  0x45,0x6d,0x4a,0x4a,0x44,0x45,0x4a,0x4a,0x00,0x00,0x00,0x02,0x0d,0x06,0x06,
  0x06,0x06,0x0e,0x00,0x00,0x00,0x00,0x06,0x06,0x06,0x00,0x06,0x06,0x02,0x06,
  0x00,0x0a,0x0a,0x07,0x07,0x06,0x02,0x05,0x05,0x02,0x02,0x00,0x00,0x04,0x04,
  0x04,0x04,0x00,0x00,0x00,0x0e,0x05,0x06,0x06,0x06,0x01,0x06,0x00,0x00,0x08,
  0x00,0x10,0x00,0x18,0x00,0x20,0x00,0x28,0x00,0x30,0x00,0x80,0x01,0x82,0x01,
  0x86,0x00,0xf6,0xcf,0xfe,0x3f,0xab,0x00,0xb0,0x00,0xb1,0x00,0xb3,0x00,0xba,
  0xf8,0xbb,0x00,0xc0,0x00,0xc1,0x00,0xc7,0xbf,0x62,0xff,0x00,0x8d,0xff,0x00,
  0xc4,0xff,0x00,0xc5,0xff,0x00,0xff,0xff,0xeb,0x01,0xff,0x0e,0x12,0x08,0x00,
  0x13,0x09,0x00,0x16,0x08,0x00,0x17,0x09,0x00,0x2b,0x09,0x00,0xae,0xff,0x07,
  0xb2,0xff,0x00,0xb4,0xff,0x00,0xb5,0xff,0x00,0xc3,0x01,0x00,0xc7,0xff,0xbf,
  0xe7,0x08,0x00,0xf0,0x02,0x00
};
		#endregion
	}
}