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
#ifndef DP_BPF_H
#define DP_BPF_H 1

#include <net/genetlink.h>
#include <linux/openvswitch.h>
#include <linux/filter.h>

#define DP_MAX_PLUMS 1024
#define PLUM_MAX_PORTS 1000
#define PLUM_MAX_TABLES 128
#define PLUM_MAX_REPLICATORS 256

/* number of plums must be <= 16-bit
 * plum_id 0 is the container
 * plum_id 1 is the tunnel plum
 * plum_id = [2 : MAX_PLUM_ID - 1] */
#define MIN_PLUM_ID  2

/* PLUM is short of Packet Lookup Update Modify.
 * It is using BPF program as core execution engine
 * one plum = one BPF program
 * BPF program can run BPF insns, call functions and access BPF tables
 * PLUM provides the functions that BPF can call and semantics behind it
 */

struct pcpu_port_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_mcast_packets;
	u64 rx_mcast_bytes;
	u64 tx_mcast_packets;
	u64 tx_mcast_bytes;
	struct u64_stats_sync syncp;
};

/* 'bpf_context' is passed into BPF programs
 * 'bpf_dp_context' encapsulates it
 */
struct bpf_dp_context {
	struct bpf_context context;
	struct sk_buff *skb;
	struct datapath *dp;
	struct plum_stack *stack;
};

struct plum_stack_frame {
	struct bpf_dp_context ctx;
	u32 dest; /* destination plum_id|port_id */
	u32 kmem; /* if true this stack frame came from kmem_cache_alloc */
	struct list_head link;
};

struct plum_stack {
	struct list_head list; /* link list of plum_stack_frame's */
	struct plum_stack_frame *curr_frame; /* current frame */
	int push_cnt; /* number of frames pushed */
};

struct plum_hash_elem {
	struct hlist_node hash_node;
	u32 hash;
	atomic_t hit_cnt;
	char key[0];
};

struct plum_hash_table {
	struct hlist_head *buckets;
	u32 n_buckets;
};

struct plum_lpm_elem {
	struct radix_tree_lpm_info info;
	atomic_t hit_cnt;
	char key[0]; /* u32 n_bits is at the beginning of key */
};

struct plum_lpm_table {
	struct radix_tree_root *root;
};

struct plum_elem {
	struct rcu_head rcu;
	struct plum_table *table;
};

#define PLUM_ELEM_ALIGN 8

struct plum_table {
	struct bpf_table info;
	spinlock_t lock;
	struct kmem_cache *leaf_cache;
	char *slab_name;
	u32 key_size;
	u32 leaf_size;
	u32 count;
	u32 max_entries;
};

#define PLUM_TABLE_ALIGN 8

struct plum_replicator_elem {
	struct rcu_head rcu;
	struct hlist_node hash_node;
	u32 replicator_id;
	u32 port_id;
};

struct plum {
	struct bpf_program *bpf_prog;
	struct plum_table **tables;
	struct hlist_head *replicators;
	u32 num_tables;
	atomic_t ports[PLUM_MAX_PORTS];
	u32 version;
	u32 upcall_pid;
	struct pcpu_port_stats __percpu *stats[PLUM_MAX_PORTS];
	void (*run)(struct bpf_dp_context *ctx);
};

#define MUX(plum, port) ((((u32)plum) << 16) | (((u32)port) & 0xffff))

#define PLUM_TABLES 0x01
#define PLUM_DATA   0x02 /* replicators, stats */

extern struct kmem_cache *plum_stack_cache;

extern struct genl_family dp_bpf_genl_family;
extern struct genl_ops dp_bpf_genl_ops[OVS_BPF_CMD_MAX];

int ovs_bpf_init(void);
void ovs_bpf_exit(void);

void bpf_dp_process_received_packet(struct vport *p, struct sk_buff *skb);
struct plum *bpf_dp_register_plum(struct bpf_image *image,
				  struct plum *old_plum, bool alloc_tbl);
void bpf_dp_unregister_plum(struct plum *plum, u8 flags);
void bpf_dp_disconnect_port(struct vport *p);
int bpf_dp_channel_push_on_plum(struct datapath *, u32 plum_id, u32 port_id,
				u32 fwd_plum_id, u32 arg1, u32 arg2, u32 arg3,
				u32 arg4, struct sk_buff *skb, u32 direction);
void plum_stack_push(struct bpf_dp_context *ctx, u32 dest, int copy);
void plum_update_stats(struct plum *plum, u32 port_id, struct sk_buff *skb,
		       bool rx);

int init_plum_tables(struct plum *plum);
void cleanup_plum_tables(struct plum *plum);
void free_plum_tables(struct plum *plum);
int bpf_dp_clear_table_elements(struct plum *plum, u32 table_id);
int bpf_dp_delete_table_element(struct plum *plum, u32 table_id,
				const char *key_data);
void *bpf_dp_read_table_element(struct plum *plum, u32 table_id,
				const char *key_data, u32 *elem_size);
void *bpf_dp_read_table_element_next(struct plum *plum, u32 table_id,
				     long *row, long *last, u32 *elem_size);
int bpf_dp_update_table_element(struct plum *plum, u32 table_id,
				const char *key_data, const char *leaf_data);

int bpf_dp_replicator_del_all(struct plum *plum, u32 replicator_id);
int bpf_dp_replicator_add_port(struct plum *plum, u32 replicator_id,
			       u32 port_id);
int bpf_dp_replicator_del_port(struct plum *plum, u32 replicator_id,
			       u32 port_id);
void cleanup_plum_replicators(struct plum *plum);
extern struct bpf_callbacks bpf_plum_cb;

#endif /* dp_bpf.h */
