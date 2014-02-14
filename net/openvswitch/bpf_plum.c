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
#include <linux/rculist.h>
#include <linux/filter.h>
#include <linux/jhash.h>
#include <linux/if_vlan.h>
#include <net/ip_tunnels.h>
#include "datapath.h"

static void bpf_run_wrap(struct bpf_dp_context *ctx)
{
	struct datapath *dp = ctx->dp;
	struct plum *plum;

	plum = rcu_dereference(dp->plums[ctx->context.plum_id]);
	bpf_run(plum->bpf_prog, &ctx->context);
}

static int compare_tables(struct plum *plum, struct bpf_program *bpf_prog)
{
	int i;
	struct bpf_table *old_table, *new_table;

	if (plum->num_tables != bpf_prog->table_cnt)
		return 1;

	for (i = 0; i < bpf_prog->table_cnt; i++) {
		old_table = &plum->tables[i]->info;
		new_table = &bpf_prog->tables[i];
		if (old_table->id != new_table->id ||
		    old_table->type != new_table->type ||
		    old_table->key_size != new_table->key_size ||
		    old_table->elem_size != new_table->elem_size ||
		    old_table->max_entries != new_table->max_entries ||
		    old_table->param1 != new_table->param1)
			return 1;
	}

	return 0;
}

struct plum *bpf_dp_register_plum(struct bpf_image *image,
				  struct plum *old_plum, bool alloc_tbl)
{
	int ret;
	struct bpf_program *bpf_prog;
	struct plum *plum;
	struct hlist_head *replicators = NULL;
	int i;
	int tsize;

	union table_priv {
		struct plum_hash_table htable;
		struct plum_lpm_table ltable;
	};

	ret = bpf_load(image, &bpf_plum_cb, &bpf_prog);
	if (ret < 0) {
		pr_err("BPF load failed %d\n", ret);
		return ERR_PTR(ret);
	}

	if (old_plum && !alloc_tbl && compare_tables(old_plum, bpf_prog)) {
		ret = -EINVAL;
		goto err_free_bpf_prog;
	}

	ret = -ENOMEM;
	plum = kzalloc(sizeof(*plum), GFP_KERNEL);
	if (!plum)
		goto err_free_bpf_prog;

	plum->bpf_prog = bpf_prog;

	plum->num_tables = bpf_prog->table_cnt;

	if (!old_plum) {
		alloc_tbl = true;

		replicators = kzalloc(PLUM_MAX_REPLICATORS *
				      sizeof(struct hlist_head), GFP_KERNEL);
		if (!replicators)
			goto err_free_plum;
		plum->replicators = replicators;

		for (i = 0; i < PLUM_MAX_REPLICATORS; i++)
			INIT_HLIST_HEAD(&plum->replicators[i]);
	} else {
		if (!alloc_tbl)
			plum->tables = old_plum->tables;

		plum->replicators = old_plum->replicators;
		memcpy(&plum->ports[0], &old_plum->ports[0],
		       sizeof(old_plum->ports[0]) * PLUM_MAX_PORTS);
		memcpy(&plum->stats[0], &old_plum->stats[0],
		       sizeof(old_plum->stats[0]) * PLUM_MAX_PORTS);
	}

	if (alloc_tbl) {
		if (bpf_prog->table_cnt) {
			plum->tables = kzalloc(bpf_prog->table_cnt * sizeof(*plum->tables),
					       GFP_KERNEL);
			if (!plum->tables)
				goto err_free_replicators;

			tsize = sizeof(struct plum_table);
			tsize += ALIGN(sizeof(struct plum_table), PLUM_TABLE_ALIGN);
			tsize += sizeof(union table_priv);

			for (i = 0; i < bpf_prog->table_cnt; i++) {
				plum->tables[i] = kzalloc(tsize, GFP_KERNEL);
				if (!plum->tables[i])
					goto err_free_tables;

				memcpy(&plum->tables[i]->info, &bpf_prog->tables[i],
				       sizeof(struct bpf_table));
			}

			if (init_plum_tables(plum) < 0)
				goto err_free_table_array;
		}
	}

	if (bpf_prog->jit_image)
		plum->run = (void (*)(struct bpf_dp_context *ctx))bpf_prog->jit_image;
	else
		plum->run = bpf_run_wrap;

	return plum;

err_free_tables:
	for (i = 0; i < bpf_prog->table_cnt; i++)
		kfree(plum->tables[i]);
err_free_table_array:
	kfree(plum->tables);
err_free_replicators:
	kfree(replicators);
err_free_plum:
	kfree(plum);
err_free_bpf_prog:
	bpf_free(bpf_prog);
	return ERR_PTR(ret);
}

static void free_plum(struct plum *plum, u8 flags)
{
	int i;

	if (flags & PLUM_DATA) {
		for (i = 0; i < PLUM_MAX_PORTS; i++)
			free_percpu(plum->stats[i]);

		kfree(plum->replicators);
	}

	if (flags & PLUM_TABLES)
		free_plum_tables(plum);

	bpf_free(plum->bpf_prog);
	kfree(plum);
}

void bpf_dp_unregister_plum(struct plum *plum, u8 flags)
{
	if (!plum)
		return;

	if (flags & PLUM_DATA)
		cleanup_plum_replicators(plum);

	if (flags & PLUM_TABLES)
		cleanup_plum_tables(plum);

	/* all ports are disconnected now. flush the pipeline */
	rcu_barrier();
	free_plum(plum, flags);
}

/* Called with ovs_mutex. */
void bpf_dp_disconnect_port(struct vport *p)
{
	struct datapath *dp = p->dp;
	struct plum *plum, *dest_plum;
	u32 dest;

	if (p->port_no == OVSP_LOCAL || p->port_no >= PLUM_MAX_PORTS)
		return;

	plum = ovsl_dereference(dp->plums[0]);

	dest = atomic_read(&plum->ports[p->port_no]);
	if (dest) {
		dest_plum = ovsl_dereference(dp->plums[dest >> 16]);
		atomic_set(&dest_plum->ports[dest & 0xffff], 0);
	}
	atomic_set(&plum->ports[p->port_no], 0);
	smp_wmb();

	/* leave the stats allocated until plum is freed */
}

static int bpf_dp_ctx_init(struct bpf_dp_context *ctx)
{
	struct ovs_key_ipv4_tunnel *tun_key = OVS_CB(ctx->skb)->tun_key;

	if (skb_headroom(ctx->skb) < 64) {
		if (pskb_expand_head(ctx->skb, 64, 0, GFP_ATOMIC))
			return -ENOMEM;
	}
	ctx->context.length = ctx->skb->len;
	ctx->context.vlan_tag = vlan_tx_tag_present(ctx->skb) ?
			vlan_tx_tag_get(ctx->skb) : 0;
	ctx->context.hw_csum = (ctx->skb->ip_summed == CHECKSUM_PARTIAL);
	if (tun_key) {
		ctx->context.tun_key.tun_id =
				be32_to_cpu(be64_get_low32(tun_key->tun_id));
		ctx->context.tun_key.src_ip = be32_to_cpu(tun_key->ipv4_src);
		ctx->context.tun_key.dst_ip = be32_to_cpu(tun_key->ipv4_dst);
		ctx->context.tun_key.tos = tun_key->ipv4_tos;
		ctx->context.tun_key.ttl = tun_key->ipv4_ttl;
	} else {
		memset(&ctx->context.tun_key, 0,
		       sizeof(struct bpf_ipv4_tun_key));
	}

	return 0;
}

static int bpf_dp_ctx_copy(struct bpf_dp_context *ctx,
			   struct bpf_dp_context *orig_ctx)
{
	struct sk_buff *skb = skb_copy(orig_ctx->skb, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	ctx->context = orig_ctx->context;
	ctx->skb = skb;
	ctx->dp = orig_ctx->dp;
	ctx->stack = orig_ctx->stack;

	return 0;
}

void plum_update_stats(struct plum *plum, u32 port_id, struct sk_buff *skb,
			 bool rx)
{
	struct pcpu_port_stats *stats;
	struct ethhdr *eh = eth_hdr(skb);

	if (unlikely(!plum->stats[port_id])) /* forward on disconnected port */
		return;

	stats = this_cpu_ptr(plum->stats[port_id]);
	u64_stats_update_begin(&stats->syncp);
	if (rx) {
		if (is_multicast_ether_addr(eh->h_dest)) {
			stats->rx_mcast_packets++;
			stats->rx_mcast_bytes += skb->len;
		} else {
			stats->rx_packets++;
			stats->rx_bytes += skb->len;
		}
	} else {
		if (is_multicast_ether_addr(eh->h_dest)) {
			stats->tx_mcast_packets++;
			stats->tx_mcast_bytes += skb->len;
		} else {
			stats->tx_packets++;
			stats->tx_bytes += skb->len;
		}
	}
	u64_stats_update_end(&stats->syncp);
}


/* called by execute_plums() to execute BPF program
 * or send it out of vport if destination plum_id is zero
 * It's called with rcu_read_lock.
 */
static void __bpf_forward(struct bpf_dp_context *ctx, u32 dest)
{
	struct datapath *dp = ctx->dp;
	u32 plum_id = dest >> 16;
	u32 port_id = dest & 0xffff;
	struct plum *plum;
	struct vport *vport;
	struct ovs_key_ipv4_tunnel tun_key;

	plum = rcu_dereference(dp->plums[plum_id]);
	if (unlikely(!plum)) {
		kfree_skb(ctx->skb);
		return;
	}
	if (plum_id == 0) {
		if (ctx->context.tun_key.dst_ip) {
			tun_key.tun_id =
				cpu_to_be64(ctx->context.tun_key.tun_id);
			tun_key.ipv4_src =
				cpu_to_be32(ctx->context.tun_key.src_ip);
			tun_key.ipv4_dst =
				cpu_to_be32(ctx->context.tun_key.dst_ip);
			tun_key.ipv4_tos = ctx->context.tun_key.tos;
			tun_key.ipv4_ttl = ctx->context.tun_key.ttl;
			tun_key.tun_flags = TUNNEL_KEY;
			OVS_CB(ctx->skb)->tun_key = &tun_key;
		} else {
			OVS_CB(ctx->skb)->tun_key = NULL;
		}

		plum_update_stats(plum, port_id, ctx->skb, false);

		vport = ovs_vport_rcu(dp, port_id);
		if (unlikely(!vport)) {
			kfree_skb(ctx->skb);
			return;
		}

	} else {
		ctx->context.port_id = port_id;
		ctx->context.plum_id = plum_id;
		BUG_ON(plum->run == NULL);
		plum_update_stats(plum, port_id, ctx->skb, true);
		/* execute BPF program */
		plum->run(ctx);
		consume_skb(ctx->skb);
	}
}


/* plum_stack_push() is called to enqueue plum_id|port_id pair into
 * stack of plums to be executed
 */
void plum_stack_push(struct bpf_dp_context *ctx, u32 dest, int copy)
{
	struct plum_stack *stack;
	struct plum_stack_frame *frame;

	stack = ctx->stack;

	if (stack->push_cnt > 1024)
		/* number of frames to execute is too high, ignore
		 * all further bpf_*_forward() calls
		 *
		 * this can happen if connections between plums make a loop:
		 * three bridge-plums in a loop is a valid network
		 * topology if STP is working, but kernel needs to make sure
		 * that packet doesn't loop forever
		 */
		return;

	stack->push_cnt++;

	if (!copy) {
		frame = stack->curr_frame;
		if (!frame) /* bpf_*_forward() is called 2nd time. ignore it */
			return;

		BUG_ON(&frame->ctx != ctx);
		stack->curr_frame = NULL;

		skb_get(ctx->skb);
	} else {
		frame = kmem_cache_alloc(plum_stack_cache, GFP_ATOMIC);
		if (!frame)
			return;
		frame->kmem = 1;
		if (bpf_dp_ctx_copy(&frame->ctx, ctx)) {
			kmem_cache_free(plum_stack_cache, frame);
			return;
		}
	}

	frame->dest = dest;
	list_add(&frame->link, &stack->list);
}

/* execute_plums() pops the stack and execute plums until stack is empty */
static void execute_plums(struct plum_stack *stack)
{
	struct plum_stack_frame *frame;

	while (!list_empty(&stack->list)) {
		frame = list_first_entry(&stack->list, struct plum_stack_frame,
					 link);
		list_del(&frame->link);

		/* let plum_stack_push() know which frame is current
		 * plum_stack_push() will be called by bpf_*_forward()
		 * functions from BPF program
		 */
		stack->curr_frame = frame;

		/* execute BPF program or forward skb out */
		__bpf_forward(&frame->ctx, frame->dest);

		/* when plum_stack_push() reuses the current frame while
		 * pushing it to the stack, it will set curr_frame to NULL
		 * kmem flag indicates whether frame was allocated or
		 * it's the first_frame from bpf_process_received_packet() stack
		 * free it here if it was allocated
		 */
		if (stack->curr_frame && stack->curr_frame->kmem)
			kmem_cache_free(plum_stack_cache, stack->curr_frame);
	}
}

/* packet arriving on vport processed here
 * must be called with rcu_read_lock
 */
void bpf_dp_process_received_packet(struct vport *p, struct sk_buff *skb)
{
	struct datapath *dp = p->dp;
	struct plum *plum;
	u32 dest;
	struct plum_stack stack = {};
	struct plum_stack_frame first_frame = {};
	struct plum_stack_frame *frame;
	struct bpf_dp_context *ctx;

	plum = rcu_dereference(dp->plums[0]);
	dest = atomic_read(&plum->ports[p->port_no]);

	if (dest) {
		frame = &first_frame;

		INIT_LIST_HEAD(&stack.list);
		ctx = &frame->ctx;
		ctx->stack = &stack;
		ctx->context.port_id = p->port_no;
		ctx->skb = skb;
		ctx->dp = dp;
		bpf_dp_ctx_init(ctx);

		plum_update_stats(plum, p->port_no, skb, true);

		frame->dest = dest;
		stack.curr_frame = NULL;
		list_add(&frame->link, &stack.list);
		execute_plums(&stack);
	} else {
		consume_skb(skb);
	}
}

/* userspace injects packet into plum */
int bpf_dp_channel_push_on_plum(struct datapath *dp, u32 plum_id, u32 port_id,
				u32 fwd_plum_id, u32 arg1, u32 arg2, u32 arg3,
				u32 arg4, struct sk_buff *skb, u32 direction)
{
	struct plum_stack stack = {};
	struct plum_stack_frame first_frame = {};
	struct plum_stack_frame *frame;
	struct bpf_dp_context *ctx;
	u32 dest;

	frame = &first_frame;
	frame->kmem = 0;

	INIT_LIST_HEAD(&stack.list);
	ctx = &frame->ctx;
	ctx->stack = &stack;
	ctx->skb = skb;
	ctx->dp = dp;
	bpf_dp_ctx_init(ctx);

	rcu_read_lock();

	if (direction == OVS_BPF_OUT_DIR) {
		ctx->context.plum_id = plum_id;
		stack.curr_frame = frame;
		bpf_forward(&ctx->context, port_id);
		execute_plums(&stack);
		consume_skb(skb);
	} else if (direction == OVS_BPF_IN_DIR) {
		dest = MUX(plum_id, port_id);
		frame->dest = dest;
		stack.curr_frame = NULL;
		list_add(&frame->link, &stack.list);
		execute_plums(&stack);
	} else if (direction == OVS_BPF_FWD_TO_PLUM) {
		ctx->context.plum_id = plum_id;
		ctx->context.arg1 = arg1;
		ctx->context.arg2 = arg2;
		ctx->context.arg3 = arg3;
		ctx->context.arg4 = arg4;
		stack.curr_frame = frame;
		bpf_forward_to_plum(&ctx->context, fwd_plum_id);
		execute_plums(&stack);
		consume_skb(skb);
	}

	rcu_read_unlock();

	return 0;
}

/* from current_plum_id:port_id find next_plum_id:next_port_id
 * and queue the packet to that plum
 *
 * plum can still modify the packet, but it's not recommended
 * all subsequent bpf_forward()/bpf_forward_self()/bpf_forward_to_plum()
 * calls from this plum will be ignored
 */
void bpf_forward(struct bpf_context *pctx, u32 port_id)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct datapath *dp = ctx->dp;
	struct plum *plum;
	u32 dest;

	if (unlikely(!ctx->skb) || port_id >= PLUM_MAX_PORTS)
		return;

	plum = rcu_dereference(dp->plums[pctx->plum_id]);
	if (unlikely(!plum)) /* plum was unregistered while running */
		return;

	dest = atomic_read(&plum->ports[port_id]);
	if (dest) {
		plum_update_stats(plum, port_id, ctx->skb, false);
		plum_stack_push(ctx, dest, 0);
	}
}

/* from current_plum_id:port_id find next_plum_id:next_port_id
 * copy the packet and queue the copy to that plum
 *
 * later plum can modify the packet and potentially forward it other port
 * bpf_clone_forward() can be called any number of times
 */
void bpf_clone_forward(struct bpf_context *pctx, u32 port_id)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct datapath *dp = ctx->dp;
	struct plum *plum;
	u32 dest;

	if (unlikely(!ctx->skb) || port_id >= PLUM_MAX_PORTS)
		return;

	plum = rcu_dereference(dp->plums[pctx->plum_id]);
	if (unlikely(!plum))
		return;

	dest = atomic_read(&plum->ports[port_id]);
	if (dest)
		plum_stack_push(ctx, dest, 1);
}

/* re-queue the packet to plum's own port
 *
 * all subsequent bpf_forward()/bpf_forward_self()/bpf_forward_to_plum()
 * calls from this plum will be ignored
 */
void bpf_forward_self(struct bpf_context *pctx, u32 port_id)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct datapath *dp = ctx->dp;
	struct plum *plum;
	u32 dest;

	if (unlikely(!ctx->skb) || port_id >= PLUM_MAX_PORTS)
		return;

	plum = rcu_dereference(dp->plums[pctx->plum_id]);
	if (unlikely(!plum))
		return;

	dest = MUX(pctx->plum_id, port_id);
	if (dest) {
		plum_update_stats(plum, port_id, ctx->skb, false);
		plum_stack_push(ctx, dest, 0);
	}
}

/* queue the packet to port zero of different plum
 *
 * all subsequent bpf_forward()/bpf_forward_self()/bpf_forward_to_plum()
 * calls from this plum will be ignored
 */
void bpf_forward_to_plum(struct bpf_context *pctx, u32 plum_id)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct datapath *dp = ctx->dp;
	struct plum *plum;
	u32 dest;

	if (unlikely(!ctx->skb) || plum_id >= DP_MAX_PLUMS)
		return;

	plum = rcu_dereference(dp->plums[pctx->plum_id]);
	if (unlikely(!plum)) /* plum was unregistered while running */
		return;

	dest = MUX(plum_id, 0);
	if (dest)
		plum_stack_push(ctx, dest, 0);
}

/* called from BPF program, therefore rcu_read_lock is held
 * bpf_check() verified that pctx is a valid pointer
 */
u8 bpf_load_byte(struct bpf_context *pctx, u32 off)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;

	if (unlikely(!skb))
		return 0;
	if (!pskb_may_pull(skb, off + 1))
		return 0;
	return *(u8 *)(skb->data + off);
}

u16 bpf_load_half(struct bpf_context *pctx, u32 off)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;

	if (unlikely(!skb))
		return 0;
	if (!pskb_may_pull(skb, off + 2))
		return 0;
	return *(u16 *)(skb->data + off);
}

u32 bpf_load_word(struct bpf_context *pctx, u32 off)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;

	if (unlikely(!skb))
		return 0;
	if (!pskb_may_pull(skb, off + 4))
		return 0;
	return *(u32 *)(skb->data + off);
}

u64 bpf_load_dword(struct bpf_context *pctx, u32 off)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;

	if (unlikely(!skb))
		return 0;
	if (!pskb_may_pull(skb, off + 8))
		return 0;
	return *(u64 *)(skb->data + off);
}

int bpf_load_bits(struct bpf_context *pctx, u32 off, void *to, u32 len)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;

	if (unlikely(!skb))
		return -EFAULT;
	if (!pskb_may_pull(skb, off + len))
		return -EFAULT;
	memcpy(to, skb->data + off, len);

	return 0;
}

static void update_skb_csum(struct sk_buff *skb, u32 from, u32 to)
{
	u32 diff[] = { ~from, to };

	skb->csum = ~csum_partial(diff, sizeof(diff), ~skb->csum);
}

void bpf_store_byte(struct bpf_context *pctx, u32 off, u8 val)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;
	u8 old = 0;
	u16 from, to;

	if (unlikely(!skb))
		return;
	if (!pskb_may_pull(skb, off + 1))
		return;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		old = *(u8 *)(skb->data + off);

	*(u8 *)(skb->data + off) = val;

	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		from = (off & 0x1) ? htons(old) : htons(old << 8);
		to = (off & 0x1) ? htons(val) : htons(val << 8);
		update_skb_csum(skb, (u32)from, (u32)to);
	}
}

void bpf_store_half(struct bpf_context *pctx, u32 off, u16 val)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;
	u16 old = 0;

	if (unlikely(!skb))
		return;
	if (!pskb_may_pull(skb, off + 2))
		return;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		old = *(u16 *)(skb->data + off);

	*(u16 *)(skb->data + off) = val;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		update_skb_csum(skb, (u32)old, (u32)val);
}

void bpf_store_word(struct bpf_context *pctx, u32 off, u32 val)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;
	u32 old = 0;

	if (unlikely(!skb))
		return;
	if (!pskb_may_pull(skb, off + 4))
		return;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		old = *(u32 *)(skb->data + off);

	*(u32 *)(skb->data + off) = val;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		update_skb_csum(skb, old, val);
}

void bpf_store_dword(struct bpf_context *pctx, u32 off, u64 val)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;
	u64 old = 0;
	u32 *from, *to;
	u32 diff[4];

	if (unlikely(!skb))
		return;
	if (!pskb_may_pull(skb, off + 8))
		return;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		old = *(u64 *)(skb->data + off);

	*(u64 *)(skb->data + off) = val;

	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		from = (u32 *)&old;
		to = (u32 *)&val;
		diff[0] = ~from[0],
		diff[1] = ~from[1],
		diff[2] = to[0],
		diff[3] = to[0],
		skb->csum = ~csum_partial(diff, sizeof(diff), ~skb->csum);
	}
}

void bpf_store_bits(struct bpf_context *pctx, u32 off, const void *from,
		    u32 len)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;

	if (unlikely(!skb))
		return;
	if (!pskb_may_pull(skb, off + len))
		return;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum,
				     csum_partial(skb->data + off, len, 0));

	memcpy(skb->data + off, from, len);


	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_add(skb->csum,
				     csum_partial(skb->data + off, len, 0));
}

/* return time in microseconds */
u64 bpf_get_usec_time(void)
{
	struct timespec now;
	getnstimeofday(&now);
	return (((u64)now.tv_sec) * 1000000) + now.tv_nsec / 1000;
}

/* called from BPF program, therefore rcu_read_lock is held
 * bpf_check() verified that 'buf' pointer to BPF's stack
 * and it has 'len' bytes for us to read
 */
void bpf_channel_push_struct(struct bpf_context *pctx, u32 struct_id,
			     const void *buf, u32 len)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct dp_upcall_info upcall;
	struct plum *plum;
	struct nlattr *nla;

	if (unlikely(!ctx->skb))
		return;

	plum = rcu_dereference(ctx->dp->plums[pctx->plum_id]);
	if (unlikely(!plum))
		return;

	/* allocate temp nlattr to pass it into ovs_dp_upcall */
	nla = kzalloc(nla_total_size(4 + len), GFP_ATOMIC);
	if (unlikely(!nla))
		return;

	nla->nla_type = OVS_PACKET_ATTR_USERDATA;
	nla->nla_len = nla_attr_size(4 + len);
	memcpy(nla_data(nla), &struct_id, 4);
	memcpy(nla_data(nla) + 4, buf, len);

	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.key = NULL;
	upcall.userdata = nla;
	upcall.portid = plum->upcall_pid;
	ovs_dp_upcall(ctx->dp, NULL, &upcall);
	kfree(nla);
}

/* called from BPF program, therefore rcu_read_lock is held */
void bpf_channel_push_packet(struct bpf_context *pctx)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct dp_upcall_info upcall;
	struct sk_buff *nskb;
	struct plum *plum;

	if (unlikely(!ctx->skb))
		return;

	plum = rcu_dereference(ctx->dp->plums[pctx->plum_id]);
	if (unlikely(!plum))
		return;

	/* queue_gso_packets() inside ovs_dp_upcall() changes skb,
	 * so copy it here, since BPF program might still be using it
	 */
	nskb = skb_clone(ctx->skb, GFP_ATOMIC);
	if (unlikely(!nskb))
		return;

	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.key = NULL;
	upcall.userdata = NULL;
	upcall.portid = plum->upcall_pid;
	/* don't exit earlier even if upcall_pid is invalid,
	 * since we want 'lost' count to be incremented
	 */
	/* disable softirq to make sure that genlmsg_unicast()->gfp_any() picks
	 * GFP_ATOMIC flag
	 * note that bpf_channel_push_struct() doesn't need to do it,
	 * since skb==NULL
	 */
	local_bh_disable();
	ovs_dp_upcall(ctx->dp, nskb, &upcall);
	local_bh_enable();
	consume_skb(nskb);
}

int bpf_push_vlan(struct bpf_context *pctx, u16 proto, u16 vlan)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;
	u16 current_tag;

	if (unlikely(!skb))
		return -EINVAL;

	if (vlan_tx_tag_present(skb)) {
		current_tag = vlan_tx_tag_get(skb);

		if (!__vlan_put_tag(skb, skb->vlan_proto, current_tag)) {
			ctx->skb = NULL;
			return -ENOMEM;
		}

		if (skb->ip_summed == CHECKSUM_COMPLETE)
			skb->csum = csum_add(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));
		ctx->context.length = skb->len;
	}
	__vlan_hwaccel_put_tag(skb, proto, vlan);
	ctx->context.vlan_tag = vlan;

	return 0;
}

int bpf_pop_vlan(struct bpf_context *pctx)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct sk_buff *skb = ctx->skb;

	if (unlikely(!skb))
		return -EINVAL;

	ctx->context.vlan_tag = 0;
	if (vlan_tx_tag_present(skb)) {
		skb->vlan_tci = 0;
	} else {
		if (skb->protocol != htons(ETH_P_8021Q) ||
		    skb->len < VLAN_ETH_HLEN)
			return 0;

		if (!pskb_may_pull(skb, ETH_HLEN))
			return 0;

		__skb_pull(skb, ETH_HLEN);
		skb = vlan_untag(skb);
		if (!skb) {
			ctx->skb = NULL;
			return -ENOMEM;
		}
		__skb_push(skb, ETH_HLEN);

		skb->vlan_tci = 0;
		ctx->context.length = skb->len;
		ctx->skb = skb;
	}
	/* move next vlan tag to hw accel tag */
	if (skb->protocol != htons(ETH_P_8021Q) ||
	    skb->len < VLAN_ETH_HLEN)
		return 0;

	if (!pskb_may_pull(skb, ETH_HLEN))
		return 0;

	__skb_pull(skb, ETH_HLEN);
	skb = vlan_untag(skb);
	if (!skb) {
		ctx->skb = NULL;
		return -ENOMEM;
	}
	__skb_push(skb, ETH_HLEN);

	ctx->context.vlan_tag = vlan_tx_tag_get(skb);
	ctx->context.length = skb->len;
	ctx->skb = skb;

	return 0;
}

u16 bpf_checksum(const u8 *buf, u32 len)
{
	/* if 'buf' points to BPF program stack, bpf_check()
	 * verified that 'len' bytes of it are valid
	 * len/4 rounds the length down, so that memory is safe to access
	 */
	return ip_fast_csum(buf, len/4);
}

u16 bpf_checksum_pkt(struct bpf_context *pctx, u32 off, u32 len)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	if (!ctx->skb)
		return 0;
	if (!pskb_may_pull(ctx->skb, off + len))
		return 0;
	/* linearized all the way till 'off + len' byte of the skb
	 * can compute checksum now
	 */
	return bpf_checksum(ctx->skb->data + off, len);
}

u16 bpf_csum_replace2(u16 csum, u16 from, u16 to)
{
	return bpf_csum_replace4(csum, (u32)from, (u32)to);
}

u16 bpf_csum_replace4(u16 csum, u32 from, u32 to)
{
	csum_replace4(&csum, from, to);
	return csum;
}

u16 bpf_pseudo_csum_replace2(u16 csum, u16 from, u16 to)
{
	return bpf_pseudo_csum_replace4(csum, (u32)from, (u32)to);
}

u16 bpf_pseudo_csum_replace4(u16 csum, u32 from, u32 to)
{
	u32 diff[] = { ~from, to };
	return ~csum_fold(csum_partial(diff, sizeof(diff),
			  csum_unfold(csum)));
}

