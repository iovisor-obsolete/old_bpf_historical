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
#include <linux/openvswitch.h>

#define MAX_CTX_OFF sizeof(struct bpf_context)

static const struct bpf_context_access ctx_access[MAX_CTX_OFF] = {
	[offsetof(struct bpf_context, port_id)] = {
		FIELD_SIZEOF(struct bpf_context, port_id),
		BPF_READ
	},
	[offsetof(struct bpf_context, plum_id)] = {
		FIELD_SIZEOF(struct bpf_context, plum_id),
		BPF_READ
	},
	[offsetof(struct bpf_context, length)] = {
		FIELD_SIZEOF(struct bpf_context, length),
		BPF_READ
	},
	[offsetof(struct bpf_context, arg1)] = {
		FIELD_SIZEOF(struct bpf_context, arg1),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, arg2)] = {
		FIELD_SIZEOF(struct bpf_context, arg2),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, arg3)] = {
		FIELD_SIZEOF(struct bpf_context, arg3),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, arg4)] = {
		FIELD_SIZEOF(struct bpf_context, arg4),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, vlan_tag)] = {
		FIELD_SIZEOF(struct bpf_context, vlan_tag),
		BPF_READ
	},
	[offsetof(struct bpf_context, hw_csum)] = {
		FIELD_SIZEOF(struct bpf_context, hw_csum),
		BPF_READ
	},
	[offsetof(struct bpf_context, capture)] = {
		FIELD_SIZEOF(struct bpf_context, capture),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, tun_key.tun_id)] = {
		FIELD_SIZEOF(struct bpf_context, tun_key.tun_id),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, tun_key.src_ip)] = {
		FIELD_SIZEOF(struct bpf_context, tun_key.src_ip),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, tun_key.dst_ip)] = {
		FIELD_SIZEOF(struct bpf_context, tun_key.dst_ip),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, tun_key.tos)] = {
		FIELD_SIZEOF(struct bpf_context, tun_key.tos),
		BPF_READ | BPF_WRITE
	},
	[offsetof(struct bpf_context, tun_key.ttl)] = {
		FIELD_SIZEOF(struct bpf_context, tun_key.ttl),
		BPF_READ | BPF_WRITE
	},
};

static const struct bpf_context_access *get_context_access(int off)
{
	if (off >= MAX_CTX_OFF)
		return NULL;
	return &ctx_access[off];
}

static const struct bpf_func_proto funcs[] = {
	[FUNC_bpf_load_byte] = {RET_INTEGER, PTR_TO_CTX},
	[FUNC_bpf_load_half] = {RET_INTEGER, PTR_TO_CTX},
	[FUNC_bpf_load_word] = {RET_INTEGER, PTR_TO_CTX},
	[FUNC_bpf_load_dword] = {RET_INTEGER, PTR_TO_CTX},
	[FUNC_bpf_load_bits] = {RET_INTEGER, PTR_TO_CTX, CONST_ARG,
				PTR_TO_STACK_IMM, CONST_ARG},
	[FUNC_bpf_store_byte] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_store_half] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_store_word] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_store_dword] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_store_bits] = {RET_INTEGER, PTR_TO_CTX, CONST_ARG,
				 PTR_TO_STACK_IMM, CONST_ARG},
	[FUNC_bpf_channel_push_struct] = {RET_VOID, PTR_TO_CTX, CONST_ARG,
					  PTR_TO_STACK_IMM, CONST_ARG},
	[FUNC_bpf_channel_push_packet] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_forward] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_forward_self] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_forward_to_plum] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_clone_forward] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_replicate] = {RET_VOID, PTR_TO_CTX},
	[FUNC_bpf_checksum] = {RET_INTEGER, PTR_TO_STACK_IMM, CONST_ARG},
	[FUNC_bpf_checksum_pkt] = {RET_INTEGER, PTR_TO_CTX},
	[FUNC_bpf_csum_replace2] = {RET_INTEGER},
	[FUNC_bpf_csum_replace4] = {RET_INTEGER},
	[FUNC_bpf_pseudo_csum_replace2] = {RET_INTEGER},
	[FUNC_bpf_pseudo_csum_replace4] = {RET_INTEGER},
	[FUNC_bpf_get_usec_time] = {RET_INTEGER},
	[FUNC_bpf_push_vlan] = {RET_INTEGER, PTR_TO_CTX},
	[FUNC_bpf_pop_vlan] = {RET_INTEGER, PTR_TO_CTX},
	[FUNC_bpf_max_id] = {}
};

static const struct bpf_func_proto *get_func_proto(int id)
{
	return &funcs[id];
}

static void execute_func(s32 func, u64 *regs)
{
	regs[R0] = 0;

	switch (func) {
	case FUNC_bpf_table_lookup:
		regs[R0] = (u64)bpf_table_lookup((struct bpf_context *)regs[R1],
						 (int)regs[R2],
						 (const void *)regs[R3]);
		break;
	case FUNC_bpf_table_update:
		regs[R0] = bpf_table_update((struct bpf_context *)regs[R1],
					    (int)regs[R2],
					    (const void *)regs[R3],
					    (const void *)regs[R4]);
		break;
	case FUNC_bpf_load_byte:
		regs[R0] = bpf_load_byte((struct bpf_context *)regs[R1],
					 (u32)regs[R2]);
		break;
	case FUNC_bpf_load_half:
		regs[R0] = bpf_load_half((struct bpf_context *)regs[R1],
					 (u32)regs[R2]);
		break;
	case FUNC_bpf_load_word:
		regs[R0] = bpf_load_word((struct bpf_context *)regs[R1],
					 (u32)regs[R2]);
		break;
	case FUNC_bpf_load_dword:
		regs[R0] = bpf_load_dword((struct bpf_context *)regs[R1],
					  (u32)regs[R2]);
		break;
	case FUNC_bpf_load_bits:
		regs[R0] = bpf_load_bits((struct bpf_context *)regs[R1],
					  (u32)regs[R2], (void *)regs[R3],
					  (u32)regs[R4]);
		break;
	case FUNC_bpf_store_byte:
		bpf_store_byte((struct bpf_context *)regs[R1], (u32)regs[R2],
			       (u8)regs[R3]);
		break;
	case FUNC_bpf_store_half:
		bpf_store_half((struct bpf_context *)regs[R1], (u32)regs[R2],
			       (u16)regs[R3]);
		break;
	case FUNC_bpf_store_word:
		bpf_store_word((struct bpf_context *)regs[R1], (u32)regs[R2],
			       (u32)regs[R3]);
		break;
	case FUNC_bpf_store_dword:
		bpf_store_dword((struct bpf_context *)regs[R1], (u32)regs[R2],
				(u64)regs[R3]);
		break;
	case FUNC_bpf_store_bits:
		bpf_store_bits((struct bpf_context *)regs[R1], (u32)regs[R2],
			       (const void *)regs[R3], (u32)regs[R4]);
		break;
	case FUNC_bpf_channel_push_packet:
		bpf_channel_push_packet((struct bpf_context *)regs[R1]);
		break;
	case FUNC_bpf_channel_push_struct:
		bpf_channel_push_struct((struct bpf_context *)regs[R1],
					(u32)regs[R2], (const void *)regs[R3],
					(u32)regs[R4]);
		break;
	case FUNC_bpf_forward:
		bpf_forward((struct bpf_context *)regs[R1], (u32)regs[R2]);
		break;
	case FUNC_bpf_forward_self:
		bpf_forward_self((struct bpf_context *)regs[R1], (u32)regs[R2]);
		break;
	case FUNC_bpf_forward_to_plum:
		bpf_forward_to_plum((struct bpf_context *)regs[R1],
				    (u32)regs[R2]);
		break;
	case FUNC_bpf_clone_forward:
		bpf_clone_forward((struct bpf_context *)regs[R1],
				  (u32)regs[R2]);
		break;
	case FUNC_bpf_replicate:
		bpf_replicate((struct bpf_context *)regs[R1], (u32)regs[R2],
			      (u32)regs[R3]);
		break;
	case FUNC_bpf_checksum:
		regs[R0] = bpf_checksum((const u8 *)regs[R1], (u32)regs[R2]);
		break;
	case FUNC_bpf_checksum_pkt:
		regs[R0] = bpf_checksum_pkt((struct bpf_context *)regs[R1],
					 (u32)regs[R2], (u32)regs[R3]);
		break;
	case FUNC_bpf_csum_replace2:
		regs[R0] = bpf_csum_replace2((u16)regs[R1], (u16)regs[R2],
					     (u16)regs[R3]);
		break;
	case FUNC_bpf_csum_replace4:
		regs[R0] = bpf_csum_replace4((u16)regs[R1], (u32)regs[R2],
					     (u32)regs[R3]);
		break;
	case FUNC_bpf_pseudo_csum_replace2:
		regs[R0] = bpf_pseudo_csum_replace2((u16)regs[R1],
						    (u16)regs[R2],
						    (u16)regs[R3]);
		break;
	case FUNC_bpf_pseudo_csum_replace4:
		regs[R0] = bpf_pseudo_csum_replace4((u16)regs[R1],
						    (u32)regs[R2],
						    (u32)regs[R3]);
		break;
	case FUNC_bpf_get_usec_time:
		regs[R0] = bpf_get_usec_time();
		break;
	case FUNC_bpf_push_vlan:
		regs[R0] = bpf_push_vlan((struct bpf_context *)regs[R1],
					 (u16)regs[R2], (u16)regs[R3]);
		break;
	case FUNC_bpf_pop_vlan:
		regs[R0] = bpf_pop_vlan((struct bpf_context *)regs[R1]);
		break;
	default:
		pr_err("unknown FUNC_bpf_%d\n", func);
		return;
	}
}

static void *jit_funcs[] = {
	[FUNC_bpf_table_lookup] = bpf_table_lookup,
	[FUNC_bpf_table_update] = bpf_table_update,
	[FUNC_bpf_load_byte] = bpf_load_byte,
	[FUNC_bpf_load_half] = bpf_load_half,
	[FUNC_bpf_load_word] = bpf_load_word,
	[FUNC_bpf_load_dword] = bpf_load_dword,
	[FUNC_bpf_load_bits] = bpf_load_bits,
	[FUNC_bpf_store_byte] = bpf_store_byte,
	[FUNC_bpf_store_half] = bpf_store_half,
	[FUNC_bpf_store_word] = bpf_store_word,
	[FUNC_bpf_store_dword] = bpf_store_dword,
	[FUNC_bpf_store_bits] = bpf_store_bits,
	[FUNC_bpf_channel_push_struct] = bpf_channel_push_struct,
	[FUNC_bpf_channel_push_packet] = bpf_channel_push_packet,
	[FUNC_bpf_forward] = bpf_forward,
	[FUNC_bpf_forward_self] = bpf_forward_self,
	[FUNC_bpf_forward_to_plum] = bpf_forward_to_plum,
	[FUNC_bpf_clone_forward] = bpf_clone_forward,
	[FUNC_bpf_replicate] = bpf_replicate,
	[FUNC_bpf_checksum] = bpf_checksum,
	[FUNC_bpf_checksum_pkt] = bpf_checksum_pkt,
	[FUNC_bpf_csum_replace2] = bpf_csum_replace2,
	[FUNC_bpf_csum_replace4] = bpf_csum_replace4,
	[FUNC_bpf_pseudo_csum_replace2] = bpf_pseudo_csum_replace2,
	[FUNC_bpf_pseudo_csum_replace4] = bpf_pseudo_csum_replace4,
	[FUNC_bpf_get_usec_time] = bpf_get_usec_time,
	[FUNC_bpf_push_vlan] = bpf_push_vlan,
	[FUNC_bpf_pop_vlan] = bpf_pop_vlan,
	[FUNC_bpf_max_id] = 0
};

static void *jit_select_func(int id)
{
	if (id < 0 || id >= FUNC_bpf_max_id)
		return NULL;
	return jit_funcs[id];
}

struct bpf_callbacks bpf_plum_cb = {
	execute_func, jit_select_func, get_func_proto, get_context_access
};

