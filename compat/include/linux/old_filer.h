#ifndef __LINUX_FILTER_WRAPPER_H
#define __LINUX_FILTER_WRAPPER_H 1

#ifdef __KERNEL__
#include_next <linux/filter.h>
#else
#include <asm-generic/int-ll64.h>
#define __user
#endif

struct bpf_insn {
	__u8	code;    /* opcode */
	__u8    a_reg:4; /* dest register*/
	__u8    x_reg:4; /* source register */
	__s16	off;     /* signed offset */
	__s32	imm;     /* signed immediate constant */
};

struct bpf_table {
	__u32   table_id;
	__u32   table_type;
	__u32   key_size;
	__u32   elem_size;
	__u32   max_entries;
	__u32   param1;         /* meaning is table-dependent */
};

struct bpf_plumlet {
	/* version > 4096 to be binary compatible with original bpf */
	__u16   version;
	__u16   stack_size;
	__u16   insn_cnt;
	__u16   table_cnt;
	struct bpf_insn __user  *insns;
	struct bpf_table __user *tables;
};

/* bpf_add|sub|...: a += x
 *         bpf_mov: a = x
 *       bpf_bswap: bswap a */
#define BPF_INSN_ALU(op, a, x) (struct bpf_insn){BPF_ALU|BPF_OP(op)|BPF_X, a, x, 0, 0}

/* bpf_add|sub|...: a += imm
 *         bpf_mov: a = imm */
#define BPF_INSN_ALU_IMM(op, a, imm) (struct bpf_insn){BPF_ALU|BPF_OP(op)|BPF_K, a, 0, 0, imm}

/* a = *(uint *) (x + off) */
#define BPF_INSN_LD(size, a, x, off) (struct bpf_insn){BPF_LDX|BPF_SIZE(size)|BPF_REL, a, x, off, 0}

/* *(uint *) (a + off) = x */
#define BPF_INSN_ST(size, a, off, x) (struct bpf_insn){BPF_STX|BPF_SIZE(size)|BPF_REL, a, x, off, 0}

/* *(uint *) (a + off) = imm */
#define BPF_INSN_ST_IMM(size, a, off, imm) (struct bpf_insn){BPF_ST|BPF_SIZE(size)|BPF_REL, a, 0, off, imm}

/* lock *(uint *) (a + off) += x */
#define BPF_INSN_XADD(size, a, off, x) (struct bpf_insn){BPF_STX|BPF_SIZE(size)|BPF_XADD, a, x, off, 0}

/* if (a 'op' x) pc += off else fall through */
#define BPF_INSN_JUMP(op, a, x, off) (struct bpf_insn){BPF_JMP|BPF_OP(op)|BPF_X, a, x, off, 0}

/* if (a 'op' imm) pc += off else fall through */
#define BPF_INSN_JUMP_IMM(op, a, imm, off) (struct bpf_insn){BPF_JMP|BPF_OP(op)|BPF_K, a, 0, off, imm}

#define BPF_INSN_RET() (struct bpf_insn){BPF_RET|BPF_K, 0, 0, 0, 0}

#define BPF_INSN_CALL(fn_code) (struct bpf_insn){BPF_JMP|BPF_CALL, 0, 0, 0, fn_code}


#define         BPF_DW          0x18
#define         BPF_REL         0xc0
#define         BPF_XADD        0xe0 /* exclusive add */

#define         BPF_MOD         0x90
#define         BPF_XOR         0xa0
#define         BPF_MOV         0xb0 /* mov reg to reg */
#define         BPF_ARSH        0xc0 /* sign extending (arithmetic) shift right */
#define         BPF_BSWAP32     0xd0 /* swap lower 4 bytes of 64-bit register */
#define         BPF_BSWAP64     0xe0 /* swap all 8 bytes of 64-bit register */

#define         BPF_JNE         0x50 /* jump != */
#define         BPF_JSGT        0x60 /* signed '>', GT in x86 */
#define         BPF_JSGE        0x70 /* signed '>=', GE in x86 */
#define         BPF_CALL        0x80 /* function call */

/* 64-bit registers */
#define         R0              0
#define         R1              1
#define         R2              2
#define         R3              3
#define         R4              4
#define         R5              5
#define         R6              6
#define         R7              7
#define         R8              8
#define         R9              9
#define         __fp__          10

/* functions */
enum {
	bpf_pe_load_byte = 1,
	bpf_pe_load_half,
	bpf_pe_load_word,
	bpf_pe_load_dword,
	bpf_pe_load_16bytes,
	bpf_pg_store_byte,
	bpf_pg_store_half,
	bpf_pg_store_word,
	bpf_pg_store_dword,
	bpf_pg_store_16bytes,
	bpf_pg_push_header,
	bpf_pg_pop_header,
	bpf_pg_channel_push,
	bpf_pe_forward,
	bpf_pg_forward_self,
	bpf_pg_clone_forward,
	bpf_pg_replicate,
	bpf_pe_hash_table_lookup,
	bpf_pg_lpm_table_lookup,
	bpf_pg_incr_cksum_u16,
	bpf_pg_incr_cksum_u32,
	bpf_pg_get_usec_time,
	bpf_pg_cksum,
	bpf_pe_push_vlan,
	bpf_pe_pop_vlan,
};

#undef SKF_AD_MAX
#define SKF_AD_ALU_XOR_X	40
#define SKF_AD_VLAN_TAG	44
#define SKF_AD_VLAN_TAG_PRESENT 48
#define SKF_AD_PAY_OFFSET	52
#define SKF_AD_MAX	56

#endif
