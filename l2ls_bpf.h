/* BPF insns */
#include "linux/filter.h"
/*.text*/
/*.align 16*/
/* set global 'bridge' */
/* asm_output_label bridge */
struct bpf_insn bpf_insns_bridge[] = {
// registers to save R6 R7
// allocate 24 bytes stack
	BPF_INSN_ALU(BPF_MOV, R6, R1), // R6 = R1
	BPF_INSN_ST_IMM(BPF_DW, __fp__ /*+*/, -24, 0), // *(uint64*)(__fp__ /*+*/, -24)=0
	BPF_INSN_ST_IMM(BPF_DW, __fp__ /*+*/, -16, 0), // *(uint64*)(__fp__ /*+*/, -16)=0
	BPF_INSN_ST_IMM(BPF_DW, __fp__ /*+*/, -8, 0), // *(uint64*)(__fp__ /*+*/, -8)=0
	BPF_INSN_LD(BPF_H, R0, R6 /*+*/, 28), // R0=(uint64)*(uint16*)(R6 /*+*/, 28)
	BPF_INSN_JUMP_IMM(BPF_JEQ, R0, 0, 4), // if (R0 == 0) goto LabelL5
	BPF_INSN_CALL(FUNC_bpf_pop_vlan), // R0=bpf_pop_vlan();
	BPF_INSN_ALU_IMM(BPF_LSH, R0, 32), // R0 <<= 32
	BPF_INSN_ALU_IMM(BPF_ARSH, R0, 32), // R0=((int64)R0)>>32
	BPF_INSN_JUMP_IMM(BPF_JNE, R0, 0, 80), // if (R0 != 0) goto LabelL21
//LabelL5:
	BPF_INSN_ALU_IMM(BPF_MOV, R4, 6), // R4 = 6
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -16), // R3 += -16
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 6), // R2 = 6
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_load_bits), // R0=bpf_load_bits();
	BPF_INSN_ALU_IMM(BPF_LSH, R0, 32), // R0 <<= 32
	BPF_INSN_ALU_IMM(BPF_ARSH, R0, 32), // R0=((int64)R0)>>32
	BPF_INSN_JUMP_IMM(BPF_JNE, R0, 0, 71), // if (R0 != 0) goto LabelL21
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -16), // R3 += -16
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 0), // R2 = 0
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_table_lookup), // R0=bpf_table_lookup();
	BPF_INSN_LD(BPF_W, R1, R6, 0), // R1=(uint64)*(uint32*)(R6, 0)
	BPF_INSN_JUMP_IMM(BPF_JEQ, R0, 0, 2), // if (R0 == 0) goto LabelL7
	BPF_INSN_LD(BPF_H, R0, R0, 0), // R0=(uint64)*(uint16*)(R0, 0)
	BPF_INSN_JUMP(BPF_JEQ, R0, R1, 8), // if (R0 == R1) goto LabelL8
//LabelL7:
	BPF_INSN_ST(BPF_H, __fp__ /*+*/, -8, R1), // *(uint16*)(__fp__ /*+*/, -8) = R1
	BPF_INSN_ALU(BPF_MOV, R4, __fp__), // R4 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R4, -8), // R4 += -8
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -16), // R3 += -16
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 0), // R2 = 0
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_table_update), // R0=bpf_table_update();
//LabelL8:
	BPF_INSN_ALU_IMM(BPF_MOV, R4, 6), // R4 = 6
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -16), // R3 += -16
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 0), // R2 = 0
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_load_bits), // R0=bpf_load_bits();
	BPF_INSN_ALU_IMM(BPF_LSH, R0, 32), // R0 <<= 32
	BPF_INSN_ALU_IMM(BPF_ARSH, R0, 32), // R0=((int64)R0)>>32
	BPF_INSN_JUMP_IMM(BPF_JNE, R0, 0, 45), // if (R0 != 0) goto LabelL21
	BPF_INSN_LD(BPF_B, R1, __fp__ /*+*/, -15), // R1=(uint64)*(uint8*)(__fp__ /*+*/, -15)
	BPF_INSN_LD(BPF_B, R0, __fp__ /*+*/, -16), // R0=(uint64)*(uint8*)(__fp__ /*+*/, -16)
	BPF_INSN_ALU(BPF_AND, R0, R1), // R0 &= R1
	BPF_INSN_LD(BPF_B, R1, __fp__ /*+*/, -14), // R1=(uint64)*(uint8*)(__fp__ /*+*/, -14)
	BPF_INSN_ALU(BPF_AND, R0, R1), // R0 &= R1
	BPF_INSN_LD(BPF_B, R1, __fp__ /*+*/, -13), // R1=(uint64)*(uint8*)(__fp__ /*+*/, -13)
	BPF_INSN_ALU(BPF_AND, R0, R1), // R0 &= R1
	BPF_INSN_LD(BPF_B, R1, __fp__ /*+*/, -12), // R1=(uint64)*(uint8*)(__fp__ /*+*/, -12)
	BPF_INSN_ALU(BPF_AND, R0, R1), // R0 &= R1
	BPF_INSN_LD(BPF_B, R1, __fp__ /*+*/, -11), // R1=(uint64)*(uint8*)(__fp__ /*+*/, -11)
	BPF_INSN_ALU(BPF_AND, R0, R1), // R0 &= R1
	BPF_INSN_ALU_IMM(BPF_AND, R0, 0xff), // R0 &= 0xff; R0 = (uint64)(uint8)R0
	BPF_INSN_JUMP_IMM(BPF_JEQ, R0, 255, 28), // if (R0 == 255) goto LabelL19
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -16), // R3 += -16
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 0), // R2 = 0
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_table_lookup), // R0=bpf_table_lookup();
	BPF_INSN_ALU(BPF_MOV, R7, R0), // R7 = R0
	BPF_INSN_JUMP_IMM(BPF_JEQ, R7, 0, 21), // if (R7 == 0) goto LabelL19
	BPF_INSN_LD(BPF_H, R0, R7, 0), // R0=(uint64)*(uint16*)(R7, 0)
	BPF_INSN_ST(BPF_H, __fp__ /*+*/, -24, R0), // *(uint16*)(__fp__ /*+*/, -24) = R0
	BPF_INSN_ALU(BPF_MOV, R3, __fp__), // R3 = __fp__
	BPF_INSN_ALU_IMM(BPF_ADD, R3, -24), // R3 += -24
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 1), // R2 = 1
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_table_lookup), // R0=bpf_table_lookup();
	BPF_INSN_JUMP_IMM(BPF_JEQ, R0, 0, 2), // if (R0 == 0) goto LabelL13
	BPF_INSN_LD(BPF_H, R3, R0, 0), // R3=(uint64)*(uint16*)(R0, 0)
	BPF_INSN_JUMP_IMM(BPF_JNE, R3, 0, 4), // if (R3 != 0) goto LabelL22
//LabelL13:
	BPF_INSN_LD(BPF_H, R2, R7, 0), // R2=(uint64)*(uint16*)(R7, 0)
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_forward), // (void)bpf_forward();
	BPF_INSN_JUMP(BPF_JA, 0, 0, 11), // goto LabelL21
//LabelL22:
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 129), // R2 = 129
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_push_vlan), // R0=bpf_push_vlan();
	BPF_INSN_ALU_IMM(BPF_LSH, R0, 32), // R0 <<= 32
	BPF_INSN_ALU_IMM(BPF_ARSH, R0, 32), // R0=((int64)R0)>>32
	BPF_INSN_JUMP_IMM(BPF_JEQ, R0, 0, -10), // if (R0 == 0) goto LabelL13
	BPF_INSN_JUMP(BPF_JA, 0, 0, 4), // goto LabelL21
//LabelL19:
	BPF_INSN_LD(BPF_W, R3, R6, 0), // R3=(uint64)*(uint32*)(R6, 0)
	BPF_INSN_ALU_IMM(BPF_MOV, R2, 1), // R2 = 1
	BPF_INSN_ALU(BPF_MOV, R1, R6), // R1 = R6
	BPF_INSN_CALL(FUNC_bpf_replicate), // (void)bpf_replicate();
//LabelL21:
	BPF_INSN_RET(), // return void /* pop 24 words */
	{0,0,0,0,0}
};
/* set global 'bridge_tables' */
/*.data*/
/*.align 4*/
/* asm_output_label bridge_tables */
unsigned int bpf_bridge_tables[] = {
  /*size=4 aligned=1*/ 0x0, /* int */
  /*size=4 aligned=1*/ 0x1, /* int */
  /*size=4 aligned=1*/ 0x8, /* int */
  /*size=4 aligned=1*/ 0x8, /* int */
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
