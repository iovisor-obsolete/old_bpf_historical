/* Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
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

/* bpf_check() is a static code analyzer that walks the BPF program
 * instruction by instruction and updates register/stack state.
 * All paths of conditional branches are analyzed until 'ret' insn.
 *
 * At the first pass depth-first-search verifies that the BPF program is a DAG.
 * It rejects the following programs:
 * - larger than 4K insns or 64 tables
 * - if loop is present (detected via back-edge)
 * - unreachable insns exist (shouldn't be a forest. program = one function)
 * - more than one ret insn
 * - ret insn is not a last insn
 * - out of bounds or malformed jumps
 * The second pass is all possible path descent from the 1st insn.
 * Conditional branch target insns keep a link list of verifier states.
 * If the state already visited, this path can be pruned.
 * If it wasn't a DAG, such state prunning would be incorrect, since it would
 * skip cycles. Since it's analyzing all pathes through the program,
 * the length of the analysis is limited to 32k insn, which may be hit even
 * if insn_cnt < 4K, but there are too many branches that change stack/regs.
 * Number of 'branches to be analyzed' is limited to 1k
 *
 * All registers are 64-bit (even on 32-bit arch)
 * R0 - return register
 * R1-R5 argument passing registers
 * R6-R9 callee saved registers
 * R10 - frame pointer read-only
 *
 * At the start of BPF program the register R1 contains a pointer to bpf_context
 * and has type PTR_TO_CTX.
 *
 * bpf_table_lookup() function returns ether pointer to table value or NULL
 * which is type PTR_TO_TABLE_CONDITIONAL. Once it passes through !=0 insn
 * the register holding that pointer in the true branch changes state to
 * PTR_TO_TABLE and the same register changes state to INVALID_PTR in the false
 * branch. See check_cond_jmp_op()
 *
 * R10 has type PTR_TO_STACK. The sequence 'mov Rx, R10; add Rx, imm' changes
 * Rx state to PTR_TO_STACK_IMM and immediate constant is saved for further
 * stack bounds checking
 *
 * registers used to pass pointers to function calls are verified against
 * function prototypes
 * Ex: before the call to bpf_table_lookup(), R1 must have type PTR_TO_CTX
 * R2 must contain integer constant and R3 PTR_TO_STACK_IMM
 * Integer constant in R2 is a table_id. It's checked that 0 <= R2 < table_cnt
 * and corresponding table_info->key_size fetched to check that
 * [R3, R3 + table_info->key_size) are within stack limits and all that stack
 * memory was initiliazed earlier by BPF program.
 * After bpf_table_lookup() call insn, R0 is set to PTR_TO_TABLE_CONDITIONAL
 * R1-R5 are cleared and no longer readable (but still writeable).
 *
 * load/store alignment is checked
 * Ex: stx [Rx + 3], (u32)Ry is rejected
 *
 * load/store to stack bounds checked and register spill is tracked
 * Ex: stx [R10 + 0], (u8)Rx is rejected
 *
 * load/store to table bounds checked and table_id provides table size
 * Ex: stx [Rx + 8], (u16)Ry is ok, if Rx is PTR_TO_TABLE and
 * 8 + sizeof(u16) <= table_info->elem_size
 *
 * load/store to bpf_context checked against known fields
 *
 * Future improvements:
 * stack size is hardcoded to 512 bytes maximum per program, relax it
 */
#define _(OP) ({ int ret = OP; if (ret < 0) return ret; })

/* JITed code allocates 512 bytes and used bottom 4 slots
 * to save R6-R9
 */
#define MAX_BPF_STACK (512 - 4 * 8)

struct reg_state {
	enum bpf_reg_type ptr;
	bool read_ok;
	int imm;
};

#define MAX_REG 11

enum bpf_stack_slot_type {
	STACK_INVALID,    /* nothing was stored in this stack slot */
	STACK_SPILL,      /* 1st byte of register spilled into stack */
	STACK_SPILL_PART, /* other 7 bytes of register spill */
	STACK_MISC	  /* BPF program wrote some data into this slot */
};

struct bpf_stack_slot {
	enum bpf_stack_slot_type type;
	enum bpf_reg_type ptr;
	int imm;
};

/* state of the program:
 * type of all registers and stack info
 */
struct verifier_state {
	struct reg_state regs[MAX_REG];
	struct bpf_stack_slot stack[MAX_BPF_STACK];
};

/* linked list of verifier states
 * used to prune search
 */
struct verifier_state_list {
	struct verifier_state state;
	struct verifier_state_list *next;
};

/* verifier_state + insn_idx are pushed to stack
 * when branch is encountered
 */
struct verifier_stack_elem {
	struct verifier_state st;
	int insn_idx; /* at insn 'insn_idx' the program state is 'st' */
	struct verifier_stack_elem *next;
};

/* single container for all structs
 * one verifier_env per bpf_check() call
 */
struct verifier_env {
	struct bpf_table *tables;
	int table_cnt;
	struct verifier_stack_elem *head;
	int stack_size;
	struct verifier_state cur_state;
	struct verifier_state_list **branch_landing;
	const struct bpf_func_proto* (*get_func_proto)(int id);
	const struct bpf_context_access *(*get_context_access)(int off);
};

static int pop_stack(struct verifier_env *env)
{
	int insn_idx;
	struct verifier_stack_elem *elem;
	if (env->head == NULL)
		return -1;
	memcpy(&env->cur_state, &env->head->st, sizeof(env->cur_state));
	insn_idx = env->head->insn_idx;
	elem = env->head->next;
	kfree(env->head);
	env->head = elem;
	env->stack_size--;
	return insn_idx;
}

static struct verifier_state *push_stack(struct verifier_env *env, int insn_idx)
{
	struct verifier_stack_elem *elem;
	elem = kmalloc(sizeof(struct verifier_stack_elem), GFP_KERNEL);
	if (!elem)
		goto err;
	memcpy(&elem->st, &env->cur_state, sizeof(env->cur_state));
	elem->insn_idx = insn_idx;
	elem->next = env->head;
	env->head = elem;
	env->stack_size++;
	if (env->stack_size > 1024) {
		pr_err("BPF program is too complex\n");
		goto err;
	}
	return &elem->st;
err:
	/* pop all elements and return */
	while (pop_stack(env) >= 0);
	return NULL;
}

#define CALLER_SAVED_REGS 6
static const int caller_saved[CALLER_SAVED_REGS] = { R0, R1, R2, R3, R4, R5 };

static void init_reg_state(struct reg_state *regs)
{
	struct reg_state *reg;
	int i;
	for (i = 0; i < MAX_REG; i++) {
		regs[i].ptr = INVALID_PTR;
		regs[i].read_ok = false;
		regs[i].imm = 0xbadbad;
	}
	reg = regs + __fp__;
	reg->ptr = PTR_TO_STACK;
	reg->read_ok = true;

	reg = regs + R1;	/* 1st arg to a function */
	reg->ptr = PTR_TO_CTX;
	reg->read_ok = true;
}

static void mark_reg_no_ptr(struct reg_state *regs, int regno)
{
	regs[regno].ptr = INVALID_PTR;
	regs[regno].imm = 0xbadbad;
	regs[regno].read_ok = true;
}

static int check_reg_arg(struct reg_state *regs, int regno, bool is_src)
{
	if (is_src) {
		if (!regs[regno].read_ok) {
			pr_err("R%d !read_ok\n", regno);
			return -EACCES;
		}
	} else {
		if (regno == __fp__)
			/* frame pointer is read only */
			return -EACCES;
		mark_reg_no_ptr(regs, regno);
	}
	return 0;
}

static int bpf_size_to_bytes(int bpf_size)
{
	if (bpf_size == BPF_W)
		return 4;
	else if (bpf_size == BPF_H)
		return 2;
	else if (bpf_size == BPF_B)
		return 1;
	else if (bpf_size == BPF_DW)
		return 8;
	else
		return -EACCES;
}

static int check_stack_write(struct verifier_state *state, int off, int size,
			     int value_regno)
{
	int i;
	struct bpf_stack_slot *slot;
	if (value_regno >= 0 &&
	    (state->regs[value_regno].ptr == PTR_TO_TABLE ||
	     state->regs[value_regno].ptr == PTR_TO_CTX)) {

		/* register containing pointer is being spilled into stack */
		if (size != 8) {
			pr_err("invalid size of register spill\n");
			return -EACCES;
		}

		slot = &state->stack[MAX_BPF_STACK + off];
		slot->type = STACK_SPILL;
		/* save register state */
		slot->ptr = state->regs[value_regno].ptr;
		slot->imm = state->regs[value_regno].imm;
		for (i = 1; i < 8; i++) {
			slot = &state->stack[MAX_BPF_STACK + off + i];
			slot->type = STACK_SPILL_PART;
		}
	} else {

		/* regular write of data into stack */
		for (i = 0; i < size; i++) {
			slot = &state->stack[MAX_BPF_STACK + off + i];
			slot->type = STACK_MISC;
		}
	}
	return 0;
}

static int check_stack_read(struct verifier_state *state, int off, int size,
			    int value_regno)
{
	int i;
	struct bpf_stack_slot *slot;

	slot = &state->stack[MAX_BPF_STACK + off];

	if (slot->type == STACK_SPILL) {
		if (size != 8) {
			pr_err("invalid size of register spill\n");
			return -EACCES;
		}
		for (i = 1; i < 8; i++) {
			if (state->stack[MAX_BPF_STACK + off + i].type !=
			    STACK_SPILL_PART) {
				pr_err("corrupted spill memory\n");
				return -EACCES;
			}
		}

		/* restore register state from stack */
		state->regs[value_regno].ptr = slot->ptr;
		state->regs[value_regno].imm = slot->imm;
		state->regs[value_regno].read_ok = true;
		return 0;
	} else {
		for (i = 0; i < size; i++) {
			if (state->stack[MAX_BPF_STACK + off + i].type !=
			    STACK_MISC) {
				pr_err("invalid read from stack off %d+%d size %d\n",
				       off, i, size);
				return -EACCES;
			}
		}
		/* have read misc data from the stack */
		mark_reg_no_ptr(state->regs, value_regno);
		return 0;
	}
}

static int get_table_info(struct verifier_env *env, int table_id,
			  struct bpf_table **table)
{
	/* if BPF program contains bpf_table_lookup(ctx, 1024, key)
	 * the incorrect table_id will be caught here
	 */
	if (table_id < 0 || table_id >= env->table_cnt) {
		pr_err("invalid access to table_id=%d max_tables=%d\n",
		       table_id, env->table_cnt);
		return -EACCES;
	}
	*table = &env->tables[table_id];
	return 0;
}

/* check read/write into table element returned by bpf_table_lookup() */
static int check_table_access(struct verifier_env *env, int regno, int off,
			      int size)
{
	struct bpf_table *table;
	int table_id = env->cur_state.regs[regno].imm;

	_(get_table_info(env, table_id, &table));

	if (off < 0 || off + size > table->elem_size) {
		pr_err("invalid access to table_id=%d leaf_size=%d off=%d size=%d\n",
		       table_id, table->elem_size, off, size);
		return -EACCES;
	}
	return 0;
}

/* check access to 'struct bpf_context' fields */
static int check_ctx_access(struct verifier_env *env, int off, int size,
			    enum bpf_access_type t)
{
	const struct bpf_context_access *access;

	if (off < 0 || off >= 32768/* struct bpf_context shouldn't be huge */)
		goto error;

	access = env->get_context_access(off);
	if (!access)
		goto error;

	if (access->size == size && (access->type & t))
		return 0;
error:
	pr_err("invalid bpf_context access off=%d size=%d\n", off, size);
	return -EACCES;
}

static int check_mem_access(struct verifier_env *env, int regno, int off,
			    int bpf_size, enum bpf_access_type t,
			    int value_regno)
{
	struct verifier_state *state = &env->cur_state;
	int size;
	_(size = bpf_size_to_bytes(bpf_size));

	if (off % size != 0) {
		pr_err("misaligned access off %d size %d\n", off, size);
		return -EACCES;
	}

	if (state->regs[regno].ptr == PTR_TO_TABLE) {
		_(check_table_access(env, regno, off, size));
		if (t == BPF_READ)
			mark_reg_no_ptr(state->regs, value_regno);
	} else if (state->regs[regno].ptr == PTR_TO_CTX) {
		_(check_ctx_access(env, off, size, t));
		if (t == BPF_READ)
			mark_reg_no_ptr(state->regs, value_regno);
	} else if (state->regs[regno].ptr == PTR_TO_STACK) {
		if (off >= 0 || off < -MAX_BPF_STACK) {
			pr_err("invalid stack off=%d size=%d\n", off, size);
			return -EACCES;
		}
		if (t == BPF_WRITE)
			_(check_stack_write(state, off, size, value_regno));
		else
			_(check_stack_read(state, off, size, value_regno));
	} else {
		pr_err("invalid mem access %d\n", state->regs[regno].ptr);
		return -EACCES;
	}
	return 0;
}

static const struct bpf_func_proto funcs[] = {
	[FUNC_bpf_table_lookup] = {PTR_TO_TABLE_CONDITIONAL, PTR_TO_CTX,
				   CONST_ARG, PTR_TO_STACK_IMM},
	[FUNC_bpf_table_update] = {RET_INTEGER, PTR_TO_CTX, CONST_ARG,
				   PTR_TO_STACK_IMM, PTR_TO_STACK_IMM},
};

static int check_func_arg(struct reg_state *regs, int regno,
			  enum bpf_reg_type expected_type, int *reg_values)
{
	struct reg_state *reg = regs + regno;
	if (expected_type == INVALID_PTR)
		return 0;

	if (!reg->read_ok) {
		pr_err("R%d !read_ok\n", regno);
		return -EACCES;
	}

	if (reg->ptr != expected_type) {
		pr_err("R%d ptr=%d expected=%d\n", regno, reg->ptr,
		       expected_type);
		return -EACCES;
	} else if (expected_type == CONST_ARG) {
		reg_values[regno] = reg->imm;
	}

	return 0;
}

/* when register 'regno' is passed into function that will read 'access_size'
 * bytes from that pointer, make sure that it's within stack boundary
 * and all elements of stack are initialized
 */
static int check_stack_boundary(struct verifier_state *state,
				struct reg_state *regs, int regno,
				int access_size)
{
	int off, i;

	if (regs[regno].ptr != PTR_TO_STACK_IMM)
		return -EACCES;

	off = regs[regno].imm;
	if (off >= 0 || off < -MAX_BPF_STACK || off + access_size > 0 ||
	    access_size <= 0) {
		pr_err("invalid stack ptr R%d off=%d access_size=%d\n",
		       regno, off, access_size);
		return -EACCES;
	}

	for (i = 0; i < access_size; i++) {
		if (state->stack[MAX_BPF_STACK + off + i].type != STACK_MISC) {
			pr_err("invalid indirect read from stack off %d+%d size %d\n",
			       off, i, access_size);
			return -EACCES;
		}
	}
	return 0;
}

static int check_call(struct verifier_env *env, int func_id)
{
	int reg_values[MAX_REG] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
	struct verifier_state *state = &env->cur_state;
	const struct bpf_func_proto *fn = NULL;
	struct reg_state *regs = state->regs;
	struct reg_state *reg;
	int i;

	/* find function prototype */
	if (func_id < 0 || func_id >= FUNC_bpf_max_id) {
		pr_err("invalid func %d\n", func_id);
		return -EINVAL;
	}

	if (func_id == FUNC_bpf_table_lookup ||
	    func_id == FUNC_bpf_table_update) {
		fn = &funcs[func_id];
	} else {
		if (env->get_func_proto)
			fn = env->get_func_proto(func_id);
		if (!fn || (fn->ret_type != RET_INTEGER &&
			    fn->ret_type != RET_VOID)) {
			pr_err("unknown func %d\n", func_id);
			return -EINVAL;
		}
	}

	/* check args */
	_(check_func_arg(regs, R1, fn->arg1_type, reg_values));
	_(check_func_arg(regs, R2, fn->arg2_type, reg_values));
	_(check_func_arg(regs, R3, fn->arg3_type, reg_values));
	_(check_func_arg(regs, R4, fn->arg4_type, reg_values));

	if (func_id == FUNC_bpf_table_lookup) {
		struct bpf_table *table;
		int table_id = reg_values[R2];

		_(get_table_info(env, table_id, &table));

		/* bpf_table_lookup(ctx, table_id, key) call: check that
		 * [key, key + table_info->key_size) are within stack limits
		 * and initialized
		 */
		_(check_stack_boundary(state, regs, R3, table->key_size));

	} else if (func_id == FUNC_bpf_table_update) {
		struct bpf_table *table;
		int table_id = reg_values[R2];

		_(get_table_info(env, table_id, &table));

		/* bpf_table_update(ctx, table_id, key, value) check
		 * that key and value are valid
		 */
		_(check_stack_boundary(state, regs, R3, table->key_size));
		_(check_stack_boundary(state, regs, R4, table->elem_size));

	} else if (fn->arg1_type == PTR_TO_STACK_IMM) {
		/* bpf_xxx(buf, len) call will access 'len' bytes
		 * from stack pointer 'buf'. Check it
		 */
		_(check_stack_boundary(state, regs, R1, reg_values[R2]));

	} else if (fn->arg2_type == PTR_TO_STACK_IMM) {
		/* bpf_yyy(arg1, buf, len) call will access 'len' bytes
		 * from stack pointer 'buf'. Check it
		 */
		_(check_stack_boundary(state, regs, R2, reg_values[R3]));

	} else if (fn->arg3_type == PTR_TO_STACK_IMM) {
		/* bpf_zzz(arg1, arg2, buf, len) call will access 'len' bytes
		 * from stack pointer 'buf'. Check it
		 */
		_(check_stack_boundary(state, regs, R3, reg_values[R4]));
	}

	/* reset caller saved regs */
	for (i = 0; i < CALLER_SAVED_REGS; i++) {
		reg = regs + caller_saved[i];
		reg->read_ok = false;
		reg->ptr = INVALID_PTR;
		reg->imm = 0xbadbad;
	}

	/* update return register */
	reg = regs + R0;
	if (fn->ret_type == RET_INTEGER) {
		reg->read_ok = true;
		reg->ptr = INVALID_PTR;
	} else if (fn->ret_type != RET_VOID) {
		reg->read_ok = true;
		reg->ptr = fn->ret_type;
		if (func_id == FUNC_bpf_table_lookup)
			/* when ret_type == PTR_TO_TABLE_CONDITIONAL
			 * remember table_id, so that check_table_access()
			 * can check 'elem_size' boundary of memory access
			 * to table element returned from bpf_table_lookup()
			 */
			reg->imm = reg_values[R2];
	}
	return 0;
}

static int check_alu_op(struct reg_state *regs, struct bpf_insn *insn)
{
	u16 opcode = BPF_OP(insn->code);

	if (opcode == BPF_BSWAP32 || opcode == BPF_BSWAP64 ||
	    opcode == BPF_NEG) {
		if (BPF_SRC(insn->code) != BPF_X)
			return -EINVAL;
		/* check src operand */
		_(check_reg_arg(regs, insn->a_reg, 1));

		/* check dest operand */
		_(check_reg_arg(regs, insn->a_reg, 0));

	} else if (opcode == BPF_MOV) {

		if (BPF_SRC(insn->code) == BPF_X)
			/* check src operand */
			_(check_reg_arg(regs, insn->x_reg, 1));

		/* check dest operand */
		_(check_reg_arg(regs, insn->a_reg, 0));

		if (BPF_SRC(insn->code) == BPF_X) {
			/* case: R1 = R2
			 * copy register state to dest reg
			 */
			regs[insn->a_reg].ptr = regs[insn->x_reg].ptr;
			regs[insn->a_reg].imm = regs[insn->x_reg].imm;
		} else {
			/* case: R = imm
			 * remember the value we stored into this reg
			 */
			regs[insn->a_reg].ptr = CONST_ARG;
			regs[insn->a_reg].imm = insn->imm;
		}

	} else {	/* all other ALU ops: and, sub, xor, add, ... */

		int stack_relative = 0;

		if (BPF_SRC(insn->code) == BPF_X)
			/* check src1 operand */
			_(check_reg_arg(regs, insn->x_reg, 1));

		/* check src2 operand */
		_(check_reg_arg(regs, insn->a_reg, 1));

		if (opcode == BPF_ADD &&
		    regs[insn->a_reg].ptr == PTR_TO_STACK &&
		    BPF_SRC(insn->code) == BPF_K)
			stack_relative = 1;

		/* check dest operand */
		_(check_reg_arg(regs, insn->a_reg, 0));

		if (stack_relative) {
			regs[insn->a_reg].ptr = PTR_TO_STACK_IMM;
			regs[insn->a_reg].imm = insn->imm;
		}
	}

	return 0;
}

static int check_cond_jmp_op(struct verifier_env *env, struct bpf_insn *insn,
			     int insn_idx)
{
	struct reg_state *regs = env->cur_state.regs;
	struct verifier_state *other_branch;
	u16 opcode = BPF_OP(insn->code);

	if (BPF_SRC(insn->code) == BPF_X)
		/* check src1 operand */
		_(check_reg_arg(regs, insn->x_reg, 1));

	/* check src2 operand */
	_(check_reg_arg(regs, insn->a_reg, 1));

	other_branch = push_stack(env, insn_idx + insn->off + 1);
	if (!other_branch)
		return -EFAULT;

	/* detect if R == 0 where R is returned value from table_lookup() */
	if (BPF_SRC(insn->code) == BPF_K &&
	    insn->imm == 0 && (opcode == BPF_JEQ ||
			       opcode == BPF_JNE) &&
	    regs[insn->a_reg].ptr == PTR_TO_TABLE_CONDITIONAL) {
		if (opcode == BPF_JEQ) {
			/* next fallthrough insn can access memory via
			 * this register
			 */
			regs[insn->a_reg].ptr = PTR_TO_TABLE;
			/* branch targer cannot access it, since reg == 0 */
			other_branch->regs[insn->a_reg].ptr = INVALID_PTR;
		} else {
			other_branch->regs[insn->a_reg].ptr = PTR_TO_TABLE;
			regs[insn->a_reg].ptr = INVALID_PTR;
		}
	}
	return 0;
}


/* non-recursive DFS pseudo code
 * 1  procedure DFS-iterative(G,v):
 * 2      label v as discovered
 * 3      let S be a stack
 * 4      S.push(v)
 * 5      while S is not empty
 * 6            t <- S.pop()
 * 7            if t is what we're looking for:
 * 8                return t
 * 9            for all edges e in G.adjacentEdges(t) do
 * 10               if edge e is already labelled
 * 11                   continue with the next edge
 * 12               w <- G.adjacentVertex(t,e)
 * 13               if vertex w is not discovered and not explored
 * 14                   label e as tree-edge
 * 15                   label w as discovered
 * 16                   S.push(w)
 * 17                   continue at 5
 * 18               else if vertex w is discovered
 * 19                   label e as back-edge
 * 20               else
 * 21                   // vertex w is explored
 * 22                   label e as forward- or cross-edge
 * 23           label t as explored
 * 24           S.pop()
 *
 * convention:
 * 1 - discovered
 * 2 - discovered and 1st branch labelled
 * 3 - discovered and 1st and 2nd branch labelled
 * 4 - explored
 */

#define STATE_END ((struct verifier_state_list *)-1)

#define PUSH_INT(I) \
	do { \
		if (cur_stack >= insn_cnt) { \
			ret = -E2BIG; \
			goto free_st; \
		} \
		stack[cur_stack++] = I; \
	} while (0)

#define PEAK_INT() \
	({ \
		int _ret; \
		if (cur_stack == 0) \
			_ret = -1; \
		else \
			_ret = stack[cur_stack - 1]; \
		_ret; \
	 })

#define POP_INT() \
	({ \
		int _ret; \
		if (cur_stack == 0) \
			_ret = -1; \
		else \
			_ret = stack[--cur_stack]; \
		_ret; \
	 })

#define PUSH_INSN(T, W, E) \
	do { \
		int w = W; \
		if (E == 1 && st[T] >= 2) \
			break; \
		if (E == 2 && st[T] >= 3) \
			break; \
		if (w >= insn_cnt) { \
			ret = -EACCES; \
			goto free_st; \
		} \
		if (E == 2) \
			/* mark branch target for state pruning */ \
			env->branch_landing[w] = STATE_END; \
		if (st[w] == 0) { \
			/* tree-edge */ \
			st[T] = 1 + E; \
			st[w] = 1; /* discovered */ \
			PUSH_INT(w); \
			goto peak_stack; \
		} else if (st[w] == 1 || st[w] == 2 || st[w] == 3) { \
			pr_err("back-edge from insn %d to %d\n", t, w); \
			ret = -EINVAL; \
			goto free_st; \
		} else if (st[w] == 4) { \
			/* forward- or cross-edge */ \
			st[T] = 1 + E; \
		} else { \
			pr_err("insn state internal bug\n"); \
			ret = -EFAULT; \
			goto free_st; \
		} \
	} while (0)

/* non-recursive depth-first-search to detect loops in BPF program
 * loop == back-edge in directed graph
 */
static int check_cfg(struct verifier_env *env, struct bpf_insn *insns,
		     int insn_cnt)
{
	int cur_stack = 0;
	int *stack;
	int ret = 0;
	int *st;
	int i, t;

	if (insns[insn_cnt - 1].code != (BPF_RET | BPF_K)) {
		pr_err("last insn is not a 'ret'\n");
		return -EINVAL;
	}

	st = kzalloc(sizeof(int) * insn_cnt, GFP_KERNEL);
	if (!st)
		return -ENOMEM;

	stack = kzalloc(sizeof(int) * insn_cnt, GFP_KERNEL);
	if (!stack) {
		kfree(st);
		return -ENOMEM;
	}

	st[0] = 1; /* mark 1st insn as discovered */
	PUSH_INT(0);

peak_stack:
	while ((t = PEAK_INT()) != -1) {
		if (t == insn_cnt - 1)
			goto mark_explored;

		if (BPF_CLASS(insns[t].code) == BPF_RET) {
			pr_err("extraneous 'ret'\n");
			ret = -EINVAL;
			goto free_st;
		}

		if (BPF_CLASS(insns[t].code) == BPF_JMP) {
			u16 opcode = BPF_OP(insns[t].code);
			if (opcode == BPF_CALL) {
				PUSH_INSN(t, t + 1, 1);
			} else if (opcode == BPF_JA) {
				if (BPF_SRC(insns[t].code) != BPF_X) {
					ret = -EINVAL;
					goto free_st;
				}
				PUSH_INSN(t, t + insns[t].off + 1, 1);
			} else {
				PUSH_INSN(t, t + 1, 1);
				PUSH_INSN(t, t + insns[t].off + 1, 2);
			}
		} else {
			PUSH_INSN(t, t + 1, 1);
		}

mark_explored:
		st[t] = 4; /* explored */
		if (POP_INT() == -1) {
			pr_err("pop_int internal bug\n");
			ret = -EFAULT;
			goto free_st;
		}
	}


	for (i = 0; i < insn_cnt; i++) {
		if (st[i] != 4) {
			pr_err("unreachable insn %d\n", i);
			ret = -EINVAL;
			goto free_st;
		}
	}

free_st:
	kfree(st);
	kfree(stack);
	return ret;
}

static int is_state_visited(struct verifier_env *env, int insn_idx)
{
	struct verifier_state_list *sl;
	struct verifier_state_list *new_sl;
	sl = env->branch_landing[insn_idx];
	if (!sl)
		/* no branch jump to this insn, ignore it */
		return 0;

	while (sl != STATE_END) {
		if (memcmp(&sl->state, &env->cur_state,
			   sizeof(env->cur_state)) == 0)
			/* reached the same register/stack state,
			 * prune the search
			 */
			return 1;
		sl = sl->next;
	}
	new_sl = kmalloc(sizeof(struct verifier_state_list), GFP_KERNEL);

	if (!new_sl)
		/* ignore kmalloc error, since it's rare and doesn't affect
		 * correctness of algorithm
		 */
		return 0;
	/* add new state to the head of linked list */
	memcpy(&new_sl->state, &env->cur_state, sizeof(env->cur_state));
	new_sl->next = env->branch_landing[insn_idx];
	env->branch_landing[insn_idx] = new_sl;
	return 0;
}

static int __bpf_check(struct verifier_env *env, struct bpf_insn *insns,
		       int insn_cnt)
{
	int insn_idx;
	int insn_processed = 0;
	struct verifier_state *state = &env->cur_state;
	struct reg_state *regs = state->regs;

	init_reg_state(regs);
	insn_idx = 0;
	for (;;) {
		struct bpf_insn *insn;
		u16 class;

		if (insn_idx >= insn_cnt) {
			pr_err("invalid insn idx %d insn_cnt %d\n",
			       insn_idx, insn_cnt);
			return -EFAULT;
		}

		insn = &insns[insn_idx];
		class = BPF_CLASS(insn->code);

		if (++insn_processed > 32768) {
			pr_err("BPF program is too large. Proccessed %d insn\n",
			       insn_processed);
			return -E2BIG;
		}

		/* pr_debug_bpf_insn(insn, NULL); */

		if (is_state_visited(env, insn_idx))
			goto process_ret;

		if (class == BPF_ALU) {
			_(check_alu_op(regs, insn));

		} else if (class == BPF_LDX) {
			if (BPF_MODE(insn->code) != BPF_REL)
				return -EINVAL;

			/* check src operand */
			_(check_reg_arg(regs, insn->x_reg, 1));

			_(check_mem_access(env, insn->x_reg, insn->off,
					   BPF_SIZE(insn->code), BPF_READ,
					   insn->a_reg));

			/* dest reg state will be updated by mem_access */

		} else if (class == BPF_STX) {
			/* check src1 operand */
			_(check_reg_arg(regs, insn->x_reg, 1));
			/* check src2 operand */
			_(check_reg_arg(regs, insn->a_reg, 1));
			_(check_mem_access(env, insn->a_reg, insn->off,
					   BPF_SIZE(insn->code), BPF_WRITE,
					   insn->x_reg));

		} else if (class == BPF_ST) {
			if (BPF_MODE(insn->code) != BPF_REL)
				return -EINVAL;
			/* check src operand */
			_(check_reg_arg(regs, insn->a_reg, 1));
			_(check_mem_access(env, insn->a_reg, insn->off,
					   BPF_SIZE(insn->code), BPF_WRITE,
					   -1));

		} else if (class == BPF_JMP) {
			u16 opcode = BPF_OP(insn->code);
			if (opcode == BPF_CALL) {
				_(check_call(env, insn->imm));
			} else if (opcode == BPF_JA) {
				if (BPF_SRC(insn->code) != BPF_X)
					return -EINVAL;
				insn_idx += insn->off + 1;
				continue;
			} else {
				_(check_cond_jmp_op(env, insn, insn_idx));
			}

		} else if (class == BPF_RET) {
process_ret:
			insn_idx = pop_stack(env);
			if (insn_idx < 0)
				break;
			else
				continue;
		}

		insn_idx++;
	}

	/* pr_debug("insn_processed %d\n", insn_processed); */
	return 0;
}

static void free_states(struct verifier_env *env, int insn_cnt)
{
	int i;

	for (i = 0; i < insn_cnt; i++) {
		struct verifier_state_list *sl = env->branch_landing[i];
		if (sl)
			while (sl != STATE_END) {
				struct verifier_state_list *sln = sl->next;
				kfree(sl);
				sl = sln;
			}
	}

	kfree(env->branch_landing);
}

int bpf_check(struct bpf_program *prog)
{
	int ret;
	struct verifier_env *env;

	if (prog->insn_cnt <= 0 || prog->insn_cnt > MAX_BPF_INSNS ||
	    prog->table_cnt < 0 || prog->table_cnt > MAX_BPF_TABLES) {
		pr_err("BPF program has %d insn and %d tables. Max is %d/%d\n",
		       prog->insn_cnt, prog->table_cnt,
		       MAX_BPF_INSNS, MAX_BPF_TABLES);
		return -E2BIG;
	}

	env = kzalloc(sizeof(struct verifier_env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;

	env->tables = prog->tables;
	env->table_cnt = prog->table_cnt;
	env->get_func_proto = prog->cb->get_func_proto;
	env->get_context_access = prog->cb->get_context_access;
	env->branch_landing = kzalloc(sizeof(struct verifier_state_list *) *
				      prog->insn_cnt, GFP_KERNEL);

	if (!env->branch_landing) {
		kfree(env);
		return -ENOMEM;
	}

	ret = check_cfg(env, prog->insns, prog->insn_cnt);
	if (ret)
		goto free_env;
	ret = __bpf_check(env, prog->insns, prog->insn_cnt);
free_env:
	while (pop_stack(env) >= 0);
	free_states(env, prog->insn_cnt);
	kfree(env);
	return ret;
}
//EXPORT_SYMBOL(bpf_check);
