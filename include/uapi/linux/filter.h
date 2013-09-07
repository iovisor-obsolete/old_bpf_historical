/* extended BPF is Copyright (c) 2011-2013, PLUMgrid, http://plumgrid.com */
/*
 * Linux Socket Filter Data Structures
 */

#ifndef _UAPI__LINUX_FILTER_H__
#define _UAPI__LINUX_FILTER_H__

/* TEMP HACK act as linux-libc-dev filter.h */
#ifdef __KERNEL__
#include <linux/compiler.h>
#else
#define __user
#endif
#include <linux/types.h>


/*
 * Current version of the filter code architecture.
 */
#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1

/*
 *	Try and keep these values and structures similar to BSD, especially
 *	the BPF code definitions which need to match so you can share filters
 */

struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};

struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter __user *filter;
};

/*
 * Instruction classes
 */

#define BPF_CLASS(code) ((code) & 0x07)
#define         BPF_LD          0x00
#define         BPF_LDX         0x01
#define         BPF_ST          0x02
#define         BPF_STX         0x03
#define         BPF_ALU         0x04
#define         BPF_JMP         0x05
#define         BPF_RET         0x06
#define         BPF_MISC        0x07

struct bpf_insn {
	__u8	code;    /* opcode */
	__u8    a_reg:4; /* dest register*/
	__u8    x_reg:4; /* source register */
	__s16	off;     /* signed offset */
	__s32	imm;     /* signed immediate constant */
};

struct bpf_table {
	__u32   id;
	__u32   type;
	__u32   key_size;
	__u32   elem_size;
	__u32   max_entries;
	__u32   param1;         /* meaning is table-dependent */
};

enum bfp_table_type {
	BPF_TABLE_HASH = 1,
};

struct bpf_image {
	/* version > 4096 to be binary compatible with original bpf */
	__u16   version;
	__u16   rsvd;
	__u16   insn_cnt;
	__u16   table_cnt;
	struct bpf_insn __user  *insns;
	struct bpf_table __user *tables;
};

/* pointer to bpf_context is the first and only argument to BPF program
 * its definition is use-case specific */
struct bpf_context;

/* bpf_add|sub|...: a += x
 *         bpf_mov: a = x
 *       bpf_bswap: bswap a */
#define BPF_INSN_ALU(op, a, x) \
	(struct bpf_insn){BPF_ALU|BPF_OP(op)|BPF_X, a, x, 0, 0}

/* bpf_add|sub|...: a += imm
 *         bpf_mov: a = imm */
#define BPF_INSN_ALU_IMM(op, a, imm) \
	(struct bpf_insn){BPF_ALU|BPF_OP(op)|BPF_K, a, 0, 0, imm}

/* a = *(uint *) (x + off) */
#define BPF_INSN_LD(size, a, x, off) \
	(struct bpf_insn){BPF_LDX|BPF_SIZE(size)|BPF_REL, a, x, off, 0}

/* *(uint *) (a + off) = x */
#define BPF_INSN_ST(size, a, off, x) \
	(struct bpf_insn){BPF_STX|BPF_SIZE(size)|BPF_REL, a, x, off, 0}

/* *(uint *) (a + off) = imm */
#define BPF_INSN_ST_IMM(size, a, off, imm) \
	(struct bpf_insn){BPF_ST|BPF_SIZE(size)|BPF_REL, a, 0, off, imm}

/* lock *(uint *) (a + off) += x */
#define BPF_INSN_XADD(size, a, off, x) \
	(struct bpf_insn){BPF_STX|BPF_SIZE(size)|BPF_XADD, a, x, off, 0}

/* if (a 'op' x) pc += off else fall through */
#define BPF_INSN_JUMP(op, a, x, off) \
	(struct bpf_insn){BPF_JMP|BPF_OP(op)|BPF_X, a, x, off, 0}

/* if (a 'op' imm) pc += off else fall through */
#define BPF_INSN_JUMP_IMM(op, a, imm, off) \
	(struct bpf_insn){BPF_JMP|BPF_OP(op)|BPF_K, a, 0, off, imm}

#define BPF_INSN_RET() \
	(struct bpf_insn){BPF_RET|BPF_K, 0, 0, 0, 0}

#define BPF_INSN_CALL(fn_code) \
	(struct bpf_insn){BPF_JMP|BPF_CALL, 0, 0, 0, fn_code}

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define         BPF_W           0x00
#define         BPF_H           0x08
#define         BPF_B           0x10
#define         BPF_DW          0x18
#define BPF_MODE(code)  ((code) & 0xe0)
#define         BPF_IMM         0x00
#define         BPF_ABS         0x20
#define         BPF_IND         0x40
#define         BPF_MEM         0x60
#define         BPF_LEN         0x80
#define         BPF_MSH         0xa0
#define         BPF_REL         0xc0
#define         BPF_XADD        0xe0 /* exclusive add */

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define         BPF_ADD         0x00
#define         BPF_SUB         0x10
#define         BPF_MUL         0x20
#define         BPF_DIV         0x30
#define         BPF_OR          0x40
#define         BPF_AND         0x50
#define         BPF_LSH         0x60
#define         BPF_RSH         0x70 /* logical shift right */
#define         BPF_NEG         0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0
#define		BPF_MOV		0xb0 /* mov reg to reg */
#define		BPF_ARSH	0xc0 /* sign extending arithmetic shift right */
#define		BPF_BSWAP32	0xd0 /* swap lower 4 bytes of 64-bit register */
#define		BPF_BSWAP64	0xe0 /* swap all 8 bytes of 64-bit register */

#define         BPF_JA          0x00
#define         BPF_JEQ         0x10 /* jump == */
#define         BPF_JGT         0x20 /* GT is unsigned '>', JA in x86 */
#define         BPF_JGE         0x30 /* GE is unsigned '>=', JAE in x86 */
#define         BPF_JSET        0x40
#define         BPF_JNE         0x50 /* jump != */
#define         BPF_JSGT        0x60 /* SGT is signed '>', GT in x86 */
#define         BPF_JSGE        0x70 /* SGE is signed '>=', GE in x86 */
#define         BPF_CALL        0x80 /* function call */
#define BPF_SRC(code)   ((code) & 0x08)
#define         BPF_K           0x00
#define         BPF_X           0x08

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

/* all types of BPF programs support at least two functions:
 * bpf_table_lookup() and bpf_table_update()
 * contents of bpf_context are use-case specific
 * BPF engine can be extended with additional functions */
enum {
	FUNC_bpf_table_lookup = 1,
	FUNC_bpf_table_update = 2,
	FUNC_bpf_max_id = 1024
};
void *bpf_table_lookup(struct bpf_context *ctx, int table_id, const void *key);
int bpf_table_update(struct bpf_context *ctx, int table_id, const void *key,
		     const void *leaf);

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)  ((code) & 0x18)
#define         BPF_A           0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

/*
 * Macros for filter block array initializers.
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

/*
 * Number of scratch memory words for: BPF_ST and BPF_STX
 */
#define BPF_MEMWORDS 16

/* RATIONALE. Negative offsets are invalid in BPF.
   We use them to reference ancillary data.
   Unlike introduction new instructions, it does not break
   existing compilers/optimizers.
 */
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PROTOCOL 0
#define SKF_AD_PKTTYPE 	4
#define SKF_AD_IFINDEX 	8
#define SKF_AD_NLATTR	12
#define SKF_AD_NLATTR_NEST	16
#define SKF_AD_MARK 	20
#define SKF_AD_QUEUE	24
#define SKF_AD_HATYPE	28
#define SKF_AD_RXHASH	32
#define SKF_AD_CPU	36
#define SKF_AD_ALU_XOR_X	40
#define SKF_AD_VLAN_TAG	44
#define SKF_AD_VLAN_TAG_PRESENT 48
#define SKF_AD_PAY_OFFSET	52
#define SKF_AD_MAX	56
#define SKF_NET_OFF   (-0x100000)
#define SKF_LL_OFF    (-0x200000)

#endif /* _UAPI__LINUX_FILTER_H__ */
