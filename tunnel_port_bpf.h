/* BPF insns */
#include "linux/filter.h"
/*.text*/
/*.align 16*/
/* set global 'tunnel' */
/* asm_output_label tunnel */
struct bpf_insn bpf_insns_tunnel[] = {
// registers to save R6
// allocate 16 bytes stack
	BPF_INSN_ALU(BPF_MOV, R6, R1), // R6 = R1
	BPF_INSN_ST_IMM(BPF_DW, __fp__ /*+*/, -16, 0), // *(uint64*)(__fp__ /*+*/, -16)=0
	BPF_INSN_ST_IMM(BPF_DW, __fp__ /*+*/, -8, 0), // *(uint64*)(__fp__ /*+*/, -8)=0
	BPF_INSN_LD(BPF_W, R2, R6, 0), // R2=(uint64)*(uint32*)(R6, 0)
	BPF_INSN_ALU(BPF_MOV, R0, R2), // R0 = R2
	BPF_INSN_ALU_IMM(BPF_ADD, R0, -1), // R0 += -1
	BPF_INSN_ALU_IMM(BPF_LSH, R0, 32), // R0 <<= 32
	BPF_INSN_ALU_IMM(BPF_RSH, R0, 32), // R0=((uint64)R0)>>32
	BPF_INSN_ALU_IMM(BPF_MOV, R3, 1), // R3 = 1
	BPF_INSN_JUMP(BPF_JGE, R3, R0, 18), // if (R3 >=/*unsign*/ R0) goto LabelL2
	BPF_INSN_ST(BPF_H, __fp__ /*+*/, -16, R2), // *(uint16*)(__fp__ /*+*/, -16) = R2
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -16), // R3 += -16
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 0), // R2 = 0
	BPF_INSN_CALL(FUNC_bpf_table_lookup), // R0=bpf_table_lookup();
	BPF_INSN_JUMP_IMM(BPF_JEQ, R0, 0, 30), // if (R0 == 0) goto LabelL15
	BPF_INSN_LD(BPF_W, R1, R0 /*+*/, 4), // R1=(uint64)*(uint32*)(R0 /*+*/, 4)
	BPF_INSN_ST(BPF_W, R6 /*+*/, 32, R1), // *(uint32*)(R6 /*+*/, 32)=R1
	BPF_INSN_LD(BPF_W, R1, R0 /*+*/, 8), // R1=(uint64)*(uint32*)(R0 /*+*/, 8)
	BPF_INSN_ST(BPF_W, R6 /*+*/, 36, R1), // *(uint32*)(R6 /*+*/, 36)=R1
	BPF_INSN_LD(BPF_W, R1, R0 /*+*/, 12), // R1=(uint64)*(uint32*)(R0 /*+*/, 12)
	BPF_INSN_ST(BPF_W, R6 /*+*/, 40, R1), // *(uint32*)(R6 /*+*/, 40)=R1
	BPF_INSN_ST_IMM(BPF_B, R6 /*+*/, 44, 0), // *(uint8*)(R6 /*+*/, 44) = 0
	BPF_INSN_ST_IMM(BPF_B, R6 /*+*/, 45, 64), // *(uint8*)(R6 /*+*/, 45) = 64
	BPF_INSN_LD(BPF_B, R2, R0, 0), // R2=(uint64)*(uint8*)(R0, 0)
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_forward), // (void)bpf_forward();
	BPF_INSN_JUMP(BPF_JA, 0, 0, 18), // goto LabelL15
//LabelL2:
	BPF_INSN_JUMP_IMM(BPF_JEQ, R2, 1, 15), // if (R2 == 1) goto LabelL16
	BPF_INSN_ALU_IMM(BPF_MOV, R0, 2), // R0 = 2
//LabelL5:
	BPF_INSN_ST(BPF_B, __fp__ /*+*/, -8, R0), // *(uint8*)(__fp__ /*+*/, -8) = R0
	BPF_INSN_LD(BPF_W, R0, R6 /*+*/, 32), // R0=(uint64)*(uint32*)(R6 /*+*/, 32)
	BPF_INSN_ST(BPF_W, __fp__ /*+*/, -4, R0), // *(uint32*)(__fp__ /*+*/, -4)=R0
	BPF_INSN_ST_IMM(BPF_W, R6 /*+*/, 40, 0), // *(uint32*)(R6 /*+*/, 40)=0
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -8), // R3 += -8
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 1), // R2 = 1
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_table_lookup), // R0=bpf_table_lookup();
	BPF_INSN_JUMP_IMM(BPF_JEQ, R0, 0, 6), // if (R0 == 0) goto LabelL15
	BPF_INSN_LD(BPF_H, R2, R0, 0), // R2=(uint64)*(uint16*)(R0, 0)
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_forward), // (void)bpf_forward();
	BPF_INSN_JUMP(BPF_JA, 0, 0, 2), // goto LabelL15
//LabelL16:
	BPF_INSN_ALU_IMM(BPF_MOV, R0, 1), // R0 = 1
	BPF_INSN_JUMP(BPF_JA, 0, 0, -16), // goto LabelL5
//LabelL15:
	BPF_INSN_RET(), // return void /* pop 16 words */
	{0,0,0,0,0}
};
/* set global 'tunnel_tables' */
/*.data*/
/*.align 4*/
/* asm_output_label tunnel_tables */
unsigned int bpf_tunnel_tables[] = {
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x1, /* int */
  /*size=4 aligned=1*/ 0x8, /* int */
  /*size=4 aligned=1*/ 0x10, /* int */
  /*size=4 aligned=1*/ 0x1000, /* int */
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x1, /* int */
  /*size=4 aligned=1*/ 0x1, /* int */
  /*size=4 aligned=1*/ 0x8, /* int */
  /*size=4 aligned=1*/ 0x8, /* int */
  /*size=4 aligned=1*/ 0x1000, /* int */
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x0, /* int */
};
