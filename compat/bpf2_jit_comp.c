/*
 * Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/filter.h>
/** begin_fixme **/
#ifdef MOD_ALLOC
void * (*module_alloc) (unsigned long size) = (void *)MOD_ALLOC;
#define module_free(A,B) vfree(B)
#include <linux/vmalloc.h>
#else
/** end_fixme **/
#include <linux/moduleloader.h>
/** begin_fixme **/
#endif
/** end_fixme **/
#include "bpf_jit_comp.h"

/** begin_fixme **/
#include <linux/random.h>
struct bpf_binary_header *bpf_alloc_binary(unsigned int proglen,
						  u8 **image_ptr)
{
	unsigned int sz, hole;
	struct bpf_binary_header *header;

	/* Most of BPF filters are really small,
	 * but if some of them fill a page, allow at least
	 * 128 extra bytes to insert a random section of int3
	 */
	sz = round_up(proglen + sizeof(*header) + 128, PAGE_SIZE);
	header = module_alloc(sz);
	if (!header)
		return NULL;

	memset(header, 0xcc, sz); /* fill whole space with int3 instructions */

	header->pages = sz / PAGE_SIZE;
	hole = sz - (proglen + sizeof(*header));

	/* insert a random number of int3 instructions before BPF code */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	*image_ptr = &header->image[prandom_u32() % hole];
#else
	*image_ptr = &header->image[32 % hole];
#endif
	return header;
}
/** end_fixme **/

static inline u8 *emit_code(u8 *ptr, u32 bytes, unsigned int len)
{
	if (len == 1)
		*ptr = bytes;
	else if (len == 2)
		*(u16 *)ptr = bytes;
	else
		*(u32 *)ptr = bytes;
	return ptr + len;
}

#define EMIT(bytes, len) (prog = emit_code(prog, (bytes), (len)))

#define EMIT1(b1)		EMIT(b1, 1)
#define EMIT2(b1, b2)		EMIT((b1) + ((b2) << 8), 2)
#define EMIT3(b1, b2, b3)	EMIT((b1) + ((b2) << 8) + ((b3) << 16), 3)
#define EMIT4(b1, b2, b3, b4)	EMIT((b1) + ((b2) << 8) + ((b3) << 16) + \
				     ((b4) << 24), 4)
/* imm32 is sign extended by cpu */
#define EMIT1_off32(b1, off) \
	do {EMIT1(b1); EMIT(off, 4); } while (0)
#define EMIT2_off32(b1, b2, off) \
	do {EMIT2(b1, b2); EMIT(off, 4); } while (0)
#define EMIT3_off32(b1, b2, b3, off) \
	do {EMIT3(b1, b2, b3); EMIT(off, 4); } while (0)
#define EMIT4_off32(b1, b2, b3, b4, off) \
	do {EMIT4(b1, b2, b3, b4); EMIT(off, 4); } while (0)

/* mov A, X */
#define EMIT_mov(A, X) \
	EMIT3(add_2mod(0x48, A, X), 0x89, add_2reg(0xC0, A, X))

#define X86_JAE 0x73
#define X86_JE  0x74
#define X86_JNE 0x75
#define X86_JA  0x77
#define X86_JGE 0x7D
#define X86_JG  0x7F

static inline bool is_imm8(__s32 value)
{
	return value <= 127 && value >= -128;
}

static inline bool is_simm32(__s64 value)
{
	return value == (__s64)(__s32)value;
}

static int bpf_size_to_x86_bytes(int bpf_size)
{
	if (bpf_size == BPF_W)
		return 4;
	else if (bpf_size == BPF_H)
		return 2;
	else if (bpf_size == BPF_B)
		return 1;
	else if (bpf_size == BPF_DW)
		return 4; /* imm32 */
	else
		return 0;
}

#define AUX_REG 32

/* avoid x86-64 R12 which if used as base address in memory access
 * always needs an extra byte for index */
static const int reg2hex[] = {
	[R0] = 0, /* rax */
	[R1] = 7, /* rdi */
	[R2] = 6, /* rsi */
	[R3] = 2, /* rdx */
	[R4] = 1, /* rcx */
	[R5] = 0, /* r8 */
	[R6] = 3, /* rbx callee saved */
	[R7] = 5, /* r13 callee saved */
	[R8] = 6, /* r14 callee saved */
	[R9] = 7, /* r15 callee saved */
	[__fp__] = 5, /* rbp readonly */
	[AUX_REG] = 1, /* r9 temp register */
};

/* is_ereg() == true if r8 <= reg <= r15,
 * rax,rcx,...,rbp don't need extra byte of encoding */
static inline bool is_ereg(u32 reg)
{
	if (reg == R5 || (reg >= R7 && reg <= R9) || reg == AUX_REG)
		return true;
	else
		return false;
}

static inline u8 add_1mod(u8 byte, u32 reg)
{
	if (is_ereg(reg))
		byte |= 1;
	return byte;
}
static inline u8 add_2mod(u8 byte, u32 r1, u32 r2)
{
	if (is_ereg(r1))
		byte |= 1;
	if (is_ereg(r2))
		byte |= 4;
	return byte;
}

static inline u8 add_1reg(u8 byte, u32 a_reg)
{
	return byte + reg2hex[a_reg];
}
static inline u8 add_2reg(u8 byte, u32 a_reg, u32 x_reg)
{
	return byte + reg2hex[a_reg] + (reg2hex[x_reg] << 3);
}

static u8 *select_bpf_func(struct bpf_program *prog, int id)
{
	if (id < 0 || id >= FUNC_bpf_max_id)
		return NULL;
	return prog->cb->jit_select_func(id);
}

static int do_jit(struct bpf_program *bpf_prog, int *addrs, u8 *image,
		  int oldproglen)
{
	struct bpf_insn *insn = bpf_prog->insns;
	int insn_cnt = bpf_prog->insn_cnt;
	u8 temp[64];
	int i;
	int proglen = 0;
	u8 *prog = temp;
	int stacksize = 512;

	EMIT1(0x55); /* push rbp */
	EMIT3(0x48, 0x89, 0xE5); /* mov rbp,rsp */

	/* sub rsp, stacksize */
	EMIT3_off32(0x48, 0x81, 0xEC, stacksize);
	/* mov qword ptr [rbp-X],rbx */
	EMIT3_off32(0x48, 0x89, 0x9D, -stacksize);
	/* mov qword ptr [rbp-X],r13 */
	EMIT3_off32(0x4C, 0x89, 0xAD, -stacksize + 8);
	/* mov qword ptr [rbp-X],r14 */
	EMIT3_off32(0x4C, 0x89, 0xB5, -stacksize + 16);
	/* mov qword ptr [rbp-X],r15 */
	EMIT3_off32(0x4C, 0x89, 0xBD, -stacksize + 24);

	for (i = 0; i < insn_cnt; i++, insn++) {
		const __s32 K = insn->imm;
		__u32 a_reg = insn->a_reg;
		__u32 x_reg = insn->x_reg;
		u8 b1 = 0, b2 = 0, b3 = 0;
		u8 jmp_cond;
		__s64 jmp_offset;
		int ilen;
		u8 *func;

		switch (insn->code) {
			/* ALU */
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_X:
			b1 = 0x48;
			b3 = 0xC0;
			switch (BPF_OP(insn->code)) {
			case BPF_ADD: b2 = 0x01; break;
			case BPF_SUB: b2 = 0x29; break;
			case BPF_AND: b2 = 0x21; break;
			case BPF_OR: b2 = 0x09; break;
			case BPF_XOR: b2 = 0x31; break;
			}
			EMIT3(add_2mod(b1, a_reg, x_reg), b2,
			      add_2reg(b3, a_reg, x_reg));
			break;

			/* mov A, X */
		case BPF_ALU | BPF_MOV | BPF_X:
			EMIT_mov(a_reg, x_reg);
			break;

			/* neg A */
		case BPF_ALU | BPF_NEG | BPF_X:
			EMIT3(add_1mod(0x48, a_reg), 0xF7,
			      add_1reg(0xD8, a_reg));
			break;

		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_K:
			b1 = add_1mod(0x48, a_reg);

			switch (BPF_OP(insn->code)) {
			case BPF_ADD: b3 = 0xC0; break;
			case BPF_SUB: b3 = 0xE8; break;
			case BPF_AND: b3 = 0xE0; break;
			case BPF_OR: b3 = 0xC8; break;
			}

			if (is_imm8(K))
				EMIT4(b1, 0x83, add_1reg(b3, a_reg), K);
			else
				EMIT3_off32(b1, 0x81, add_1reg(b3, a_reg), K);
			break;

		case BPF_ALU | BPF_MOV | BPF_K:
			/* 'mov rax, imm32' sign extends imm32.
			 * possible optimization: if imm32 is positive,
			 * use 'mov eax, imm32' (which zero-extends imm32)
			 * to save 2 bytes */
			b1 = add_1mod(0x48, a_reg);
			b2 = 0xC7;
			b3 = 0xC0;
			EMIT3_off32(b1, b2, add_1reg(b3, a_reg), K);
			break;

			/* A %= X
			 * A /= X */
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_X:
			EMIT1(0x50); /* push rax */
			EMIT1(0x52); /* push rdx */

			/* mov r9, X */
			EMIT_mov(AUX_REG, x_reg);

			/* mov rax, A */
			EMIT_mov(R0, a_reg);

			/* xor rdx, rdx */
			EMIT3(0x48, 0x31, 0xd2);

			/* if X==0, skip divide, make A=0 */

			/* cmp r9, 0 */
			EMIT4(0x49, 0x83, 0xF9, 0x00);

			/* je .+3 */
			EMIT2(X86_JE, 3);

			/* div r9 */
			EMIT3(0x49, 0xF7, 0xF1);

			if (BPF_OP(insn->code) == BPF_MOD) {
				/* mov r9, rdx */
				EMIT3(0x49, 0x89, 0xD1);
			} else {
				/* mov r9, rax */
				EMIT3(0x49, 0x89, 0xC1);
			}

			EMIT1(0x5A); /* pop rdx */
			EMIT1(0x58); /* pop rax */

			/* mov A, r9 */
			EMIT_mov(a_reg, AUX_REG);
			break;

			/* shifts */
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_ARSH | BPF_K:
			b1 = add_1mod(0x48, a_reg);
			switch (BPF_OP(insn->code)) {
			case BPF_LSH: b3 = 0xE0; break;
			case BPF_RSH: b3 = 0xE8; break;
			case BPF_ARSH: b3 = 0xF8; break;
			}
			EMIT4(b1, 0xC1, add_1reg(b3, a_reg), K);
			break;

		case BPF_ALU | BPF_BSWAP32 | BPF_X:
			/* emit 'bswap eax' to swap lower 4-bytes */
			if (is_ereg(a_reg))
				EMIT2(0x41, 0x0F);
			else
				EMIT1(0x0F);
			EMIT1(add_1reg(0xC8, a_reg));
			break;

		case BPF_ALU | BPF_BSWAP64 | BPF_X:
			/* emit 'bswap rax' to swap 8-bytes */
			EMIT3(add_1mod(0x48, a_reg), 0x0F,
			      add_1reg(0xC8, a_reg));
			break;

			/* ST: *(u8*)(a_reg + off) = imm */
		case BPF_ST | BPF_REL | BPF_B:
			if (is_ereg(a_reg))
				EMIT2(0x41, 0xC6);
			else
				EMIT1(0xC6);
			goto st;
		case BPF_ST | BPF_REL | BPF_H:
			if (is_ereg(a_reg))
				EMIT3(0x66, 0x41, 0xC7);
			else
				EMIT2(0x66, 0xC7);
			goto st;
		case BPF_ST | BPF_REL | BPF_W:
			if (is_ereg(a_reg))
				EMIT2(0x41, 0xC7);
			else
				EMIT1(0xC7);
			goto st;
		case BPF_ST | BPF_REL | BPF_DW:
			EMIT2(add_1mod(0x48, a_reg), 0xC7);

st:			if (is_imm8(insn->off))
				EMIT2(add_1reg(0x40, a_reg), insn->off);
			else
				EMIT1_off32(add_1reg(0x80, a_reg), insn->off);

			EMIT(K, bpf_size_to_x86_bytes(BPF_SIZE(insn->code)));
			break;

			/* STX: *(u8*)(a_reg + off) = x_reg */
		case BPF_STX | BPF_REL | BPF_B:
			/* emit 'mov byte ptr [rax + off], al' */
			if (is_ereg(a_reg) || is_ereg(x_reg) ||
			    /* have to add extra byte for x86 SIL, DIL regs */
			    x_reg == R1 || x_reg == R2)
				EMIT2(add_2mod(0x40, a_reg, x_reg), 0x88);
			else
				EMIT1(0x88);
			goto stx;
		case BPF_STX | BPF_REL | BPF_H:
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT3(0x66, add_2mod(0x40, a_reg, x_reg), 0x89);
			else
				EMIT2(0x66, 0x89);
			goto stx;
		case BPF_STX | BPF_REL | BPF_W:
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT2(add_2mod(0x40, a_reg, x_reg), 0x89);
			else
				EMIT1(0x89);
			goto stx;
		case BPF_STX | BPF_REL | BPF_DW:
			EMIT2(add_2mod(0x48, a_reg, x_reg), 0x89);
stx:			if (is_imm8(insn->off))
				EMIT2(add_2reg(0x40, a_reg, x_reg), insn->off);
			else
				EMIT1_off32(add_2reg(0x80, a_reg, x_reg),
					    insn->off);
			break;

			/* LDX: a_reg = *(u8*)(x_reg + off) */
		case BPF_LDX | BPF_REL | BPF_B:
			/* emit 'movzx rax, byte ptr [rax + off]' */
			EMIT3(add_2mod(0x48, x_reg, a_reg), 0x0F, 0xB6);
			goto ldx;
		case BPF_LDX | BPF_REL | BPF_H:
			/* emit 'movzx rax, word ptr [rax + off]' */
			EMIT3(add_2mod(0x48, x_reg, a_reg), 0x0F, 0xB7);
			goto ldx;
		case BPF_LDX | BPF_REL | BPF_W:
			/* emit 'mov eax, dword ptr [rax+0x14]' */
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT2(add_2mod(0x40, x_reg, a_reg), 0x8B);
			else
				EMIT1(0x8B);
			goto ldx;
		case BPF_LDX | BPF_REL | BPF_DW:
			/* emit 'mov rax, qword ptr [rax+0x14]' */
			EMIT2(add_2mod(0x48, x_reg, a_reg), 0x8B);
ldx:			/* if insn->off == 0 we can save one extra byte, but
			 * special case of x86 R13 which always needs an offset
			 * is not worth the pain */
			if (is_imm8(insn->off))
				EMIT2(add_2reg(0x40, x_reg, a_reg), insn->off);
			else
				EMIT1_off32(add_2reg(0x80, x_reg, a_reg),
					    insn->off);
			break;

			/* STX XADD: lock *(u8*)(a_reg + off) += x_reg */
		case BPF_STX | BPF_XADD | BPF_B:
			/* emit 'lock add byte ptr [rax + off], al' */
			if (is_ereg(a_reg) || is_ereg(x_reg) ||
			    /* have to add extra byte for x86 SIL, DIL regs */
			    x_reg == R1 || x_reg == R2)
				EMIT3(0xF0, add_2mod(0x40, a_reg, x_reg), 0x00);
			else
				EMIT2(0xF0, 0x00);
			goto xadd;
		case BPF_STX | BPF_XADD | BPF_H:
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT4(0x66, 0xF0, add_2mod(0x40, a_reg, x_reg),
				      0x01);
			else
				EMIT3(0x66, 0xF0, 0x01);
			goto xadd;
		case BPF_STX | BPF_XADD | BPF_W:
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT3(0xF0, add_2mod(0x40, a_reg, x_reg), 0x01);
			else
				EMIT2(0xF0, 0x01);
			goto xadd;
		case BPF_STX | BPF_XADD | BPF_DW:
			EMIT3(0xF0, add_2mod(0x48, a_reg, x_reg), 0x01);
xadd:			if (is_imm8(insn->off))
				EMIT2(add_2reg(0x40, a_reg, x_reg), insn->off);
			else
				EMIT1_off32(add_2reg(0x80, a_reg, x_reg),
					    insn->off);
			break;

			/* call */
		case BPF_JMP | BPF_CALL:
			func = select_bpf_func(bpf_prog, K);
			jmp_offset = func - (image + addrs[i]);
			if (!func || !is_simm32(jmp_offset)) {
				pr_err("unsupported bpf func %d addr %p image %p\n",
				       K, func, image);
				return -EINVAL;
			}
			EMIT1_off32(0xE8, jmp_offset);
			break;

			/* cond jump */
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JNE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JSGT | BPF_X:
		case BPF_JMP | BPF_JSGE | BPF_X:
			/* emit 'cmp a_reg, x_reg' insn */
			b1 = 0x48;
			b2 = 0x39;
			b3 = 0xC0;
			EMIT3(add_2mod(b1, a_reg, x_reg), b2,
			      add_2reg(b3, a_reg, x_reg));
			goto emit_jump;
		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JNE | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JSGT | BPF_K:
		case BPF_JMP | BPF_JSGE | BPF_K:
			/* emit 'cmp a_reg, imm8/32' */
			EMIT1(add_1mod(0x48, a_reg));

			if (is_imm8(K))
				EMIT3(0x83, add_1reg(0xF8, a_reg), K);
			else
				EMIT2_off32(0x81, add_1reg(0xF8, a_reg), K);

emit_jump:		/* convert BPF opcode to x86 */
			switch (BPF_OP(insn->code)) {
			case BPF_JEQ:
				jmp_cond = X86_JE;
				break;
			case BPF_JNE:
				jmp_cond = X86_JNE;
				break;
			case BPF_JGT:
				/* GT is unsigned '>', JA in x86 */
				jmp_cond = X86_JA;
				break;
			case BPF_JGE:
				/* GE is unsigned '>=', JAE in x86 */
				jmp_cond = X86_JAE;
				break;
			case BPF_JSGT:
				/* signed '>', GT in x86 */
				jmp_cond = X86_JG;
				break;
			case BPF_JSGE:
				/* signed '>=', GE in x86 */
				jmp_cond = X86_JGE;
				break;
			default: /* to silence gcc warning */
				return -EFAULT;
			}
			jmp_offset = addrs[i + insn->off] - addrs[i];
			if (is_imm8(jmp_offset)) {
				EMIT2(jmp_cond, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT2_off32(0x0F, jmp_cond + 0x10, jmp_offset);
			} else {
				pr_err("cond_jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}

			break;

		case BPF_JMP | BPF_JA | BPF_X:
			jmp_offset = addrs[i + insn->off] - addrs[i];
			if (is_imm8(jmp_offset)) {
				EMIT2(0xEB, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT1_off32(0xE9, jmp_offset);
			} else {
				pr_err("jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}

			break;

		case BPF_RET | BPF_K:
			/* mov rbx, qword ptr [rbp-X] */
			EMIT3_off32(0x48, 0x8B, 0x9D, -stacksize);
			/* mov r13, qword ptr [rbp-X] */
			EMIT3_off32(0x4C, 0x8B, 0xAD, -stacksize + 8);
			/* mov r14, qword ptr [rbp-X] */
			EMIT3_off32(0x4C, 0x8B, 0xB5, -stacksize + 16);
			/* mov r15, qword ptr [rbp-X] */
			EMIT3_off32(0x4C, 0x8B, 0xBD, -stacksize + 24);

			EMIT1(0xC9); /* leave */
			EMIT1(0xC3); /* ret */
			break;

		default:
			/*pr_debug_bpf_insn(insn, NULL);*/
			pr_err("bpf_jit: unknown opcode %02x\n", insn->code);
			return -EINVAL;
		}

		ilen = prog - temp;
		if (image) {
			if (proglen + ilen > oldproglen)
				return -2;
			memcpy(image + proglen, temp, ilen);
		}
		proglen += ilen;
		addrs[i] = proglen;
		prog = temp;
	}
	return proglen;
}

void bpf2_jit_compile(struct bpf_program *prog)
{
	struct bpf_binary_header *header = NULL;
	int proglen, oldproglen = 0;
	int *addrs;
	u8 *image = NULL;
	int pass;
	int i;

	if (!prog || !prog->cb || !prog->cb->jit_select_func)
		return;

	addrs = kmalloc(prog->insn_cnt * sizeof(*addrs), GFP_KERNEL);
	if (!addrs)
		return;

	for (proglen = 0, i = 0; i < prog->insn_cnt; i++) {
		proglen += 64;
		addrs[i] = proglen;
	}
	for (pass = 0; pass < 10; pass++) {
		proglen = do_jit(prog, addrs, image, oldproglen);
		if (proglen <= 0) {
			image = NULL;
			goto out;
		}
		if (image) {
			if (proglen != oldproglen)
				pr_err("bpf_jit: proglen=%d != oldproglen=%d\n",
				       proglen, oldproglen);
			break;
		}
		if (proglen == oldproglen) {
			header = bpf_alloc_binary(proglen, &image);
			if (!header)
				goto out;
		}
		oldproglen = proglen;
	}

	if (image) {
		bpf_flush_icache(header, image + proglen);
		set_memory_ro((unsigned long)header, header->pages);
	}
out:
	kfree(addrs);
	prog->jit_image = (void (*)(struct bpf_context *ctx))image;
	return;
}
//EXPORT_SYMBOL(bpf2_jit_compile);

static void bpf2_jit_free_deferred(struct work_struct *work)
{
	struct bpf_program *prog = container_of(work, struct bpf_program, work);
	unsigned long addr = (unsigned long)prog->jit_image & PAGE_MASK;
	struct bpf_binary_header *header = (void *)addr;

	set_memory_rw(addr, header->pages);
	module_free(NULL, header);
	free_bpf_program(prog);
}

void bpf2_jit_free(struct bpf_program *prog)
{
	if (prog->jit_image) {
		INIT_WORK(&prog->work, bpf2_jit_free_deferred);
		schedule_work(&prog->work);
	} else {
		free_bpf_program(prog);
	}
}
//EXPORT_SYMBOL(bpf2_jit_free);
