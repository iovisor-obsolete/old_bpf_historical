#ifndef __LINUX_FILTER_WRAPPER_H
#define __LINUX_FILTER_WRAPPER_H 1

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#include <uapi/linux/filter.h>
#define __LINUX_FILTER_H__
#include <linux/atomic.h>
#include <linux/rcupdate.h>
struct sk_buff;
struct sock;
struct sock_filter;
struct sk_filter
{
        atomic_t                refcnt;
        unsigned int            len;    /* Number of filter blocks */
        unsigned int            (*bpf_func)(const struct sk_buff *skb,
                                            const struct sock_filter *filter);
        struct rcu_head         rcu;
        struct sock_filter      insns[0];
};

static inline unsigned int sk_filter_len(const struct sk_filter *fp)
{
        return fp->len * sizeof(struct sock_filter) + sizeof(*fp);
}

extern int sk_filter(struct sock *sk, struct sk_buff *skb);
#else
#include_next <linux/filter.h>
#endif

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(100,1,0)
#include <linux/slab.h>
/* type of value stored in a BPF register or
 * passed into function as an argument or
 * returned from the function */
enum bpf_reg_type {
	INVALID_PTR,  /* reg doesn't contain a valid pointer */
	PTR_TO_CTX,   /* reg points to bpf_context */
	PTR_TO_TABLE, /* reg points to table element */
	PTR_TO_TABLE_CONDITIONAL, /* points to table element or NULL */
	PTR_TO_STACK,     /* reg == frame_pointer */
	PTR_TO_STACK_IMM, /* reg == frame_pointer + imm */
	RET_INTEGER, /* function returns integer */
	RET_VOID,    /* function returns void */
	CONST_ARG    /* function expects integer constant argument */
};

/* BPF function prototype */
struct bpf_func_proto {
	enum bpf_reg_type ret_type;
	enum bpf_reg_type arg1_type;
	enum bpf_reg_type arg2_type;
	enum bpf_reg_type arg3_type;
	enum bpf_reg_type arg4_type;
};

/* struct bpf_context access type */
enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2
};

struct bpf_context_access {
	int size;
	enum bpf_access_type type;
};

struct bpf_callbacks {
	/* execute BPF func_id with given registers */
	void (*execute_func)(int id, u64 *regs);

	/* return address of func_id suitable to be called from JITed program */
	void *(*jit_select_func)(int id);

	/* return BPF function prototype for verification */
	const struct bpf_func_proto* (*get_func_proto)(int id);

	/* return expected bpf_context access size and permissions
	 * for given byte offset within bpf_context */
	const struct bpf_context_access *(*get_context_access)(int off);
};

struct bpf_program {
	u16   insn_cnt;
	u16   table_cnt;
	struct bpf_insn *insns;
	struct bpf_table *tables;
	struct bpf_callbacks *cb;
	void (*jit_image)(struct bpf_context *ctx);
	struct work_struct work;
};
/* load BPF program from user space, setup callback extensions
 * and run through verifier */
int bpf_load(struct bpf_image *image, struct bpf_callbacks *cb,
	     struct bpf_program **prog);
/* free BPF program */
void bpf_free(struct bpf_program *prog);
/* execture BPF program */
void bpf_run(struct bpf_program *prog, struct bpf_context *ctx);
/* verify correctness of BPF program */
int bpf_check(struct bpf_program *prog);
/* pr_debug one BPF instructions and registers */
void pr_debug_bpf_insn(struct bpf_insn *insn, u64 *regs);

static inline void free_bpf_program(struct bpf_program *prog)
{
	kfree(prog->tables);
	kfree(prog->insns);
	kfree(prog);
}
#if defined(CONFIG_BPF_JIT) || LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
void bpf2_jit_compile(struct bpf_program *prog);
void bpf2_jit_free(struct bpf_program *prog);
#else
static inline void bpf2_jit_compile(struct bpf_program *prog)
{
}
static inline void bpf2_jit_free(struct bpf_program *prog)
{
	free_bpf_program(prog);
}
#endif
#endif

#endif
