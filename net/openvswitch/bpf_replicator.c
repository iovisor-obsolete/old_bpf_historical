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
#include "datapath.h"

static struct hlist_head *replicator_hash_bucket(const struct plum *plum,
						 u32 replicator_id)
{
	return &plum->replicators[replicator_id & (PLUM_MAX_REPLICATORS - 1)];
}

/* Must be called with rcu_read_lock. */
static
struct plum_replicator_elem *replicator_lookup_port(const struct plum *plum,
						    u32 replicator_id,
						    u32 port_id)
{
	struct hlist_head *head;
	struct plum_replicator_elem *elem;

	WARN_ON_ONCE(!rcu_read_lock_held());

	head = replicator_hash_bucket(plum, replicator_id);
	hlist_for_each_entry_rcu(elem, head, hash_node) {
		if (elem->replicator_id == replicator_id &&
		    elem->port_id == port_id)
			return elem;
	}
	return NULL;
}

int bpf_dp_replicator_del_all(struct plum *plum, u32 replicator_id)
{
	struct hlist_head *head;
	struct hlist_node *n;
	struct plum_replicator_elem *elem;

	head = replicator_hash_bucket(plum, replicator_id);
	hlist_for_each_entry_safe(elem, n, head, hash_node) {
		if (elem->replicator_id == replicator_id) {
			hlist_del_rcu(&elem->hash_node);
			kfree_rcu(elem, rcu);
		}
	}

	return 0;
}

int bpf_dp_replicator_add_port(struct plum *plum, u32 replicator_id,
			       u32 port_id)
{
	struct hlist_head *head;
	struct plum_replicator_elem *elem;

	rcu_read_lock();
	elem = replicator_lookup_port(plum, replicator_id, port_id);
	if (elem) {
		rcu_read_unlock();
		return -EEXIST;
	}
	rcu_read_unlock();

	elem = kzalloc(sizeof(*elem), GFP_KERNEL);
	if (!elem)
		return -ENOMEM;

	elem->replicator_id = replicator_id;
	elem->port_id = port_id;

	head = replicator_hash_bucket(plum, replicator_id);
	hlist_add_head_rcu(&elem->hash_node, head);

	return 0;
}

int bpf_dp_replicator_del_port(struct plum *plum, u32 replicator_id,
			       u32 port_id)
{
	struct plum_replicator_elem *elem;

	rcu_read_lock();
	elem = replicator_lookup_port(plum, replicator_id, port_id);
	if (!elem) {
		rcu_read_unlock();
		return -ENODEV;
	}

	hlist_del_rcu(&elem->hash_node);
	kfree_rcu(elem, rcu);
	rcu_read_unlock();

	return 0;
}

void cleanup_plum_replicators(struct plum *plum)
{
	int i;

	if (!plum->replicators)
		return;

	for (i = 0; i < PLUM_MAX_REPLICATORS; i++)
		bpf_dp_replicator_del_all(plum, i);
}

/* Must be called with rcu_read_lock. */
static void replicator_for_each(struct plum *plum, struct bpf_dp_context *ctx,
				u32 replicator_id, u32 src_port)
{
	struct hlist_head *head;
	struct plum_replicator_elem *elem;
	u32 dest;

	head = replicator_hash_bucket(plum, replicator_id);
	hlist_for_each_entry_rcu(elem, head, hash_node) {
		if (elem->replicator_id == replicator_id &&
		    elem->port_id != src_port) {
			dest = atomic_read(&plum->ports[elem->port_id]);
			if (dest) {
				plum_update_stats(plum, elem->port_id, ctx->skb,
						  false);
				plum_stack_push(ctx, dest, 1);
			}
		}
	}
}

void bpf_replicate(struct bpf_context *pctx, u32 replicator_id, u32 src_port)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct datapath *dp = ctx->dp;
	struct plum *plum;

	if (!ctx->skb ||
	    ctx->context.plum_id >= DP_MAX_PLUMS)
		return;

	plum = rcu_dereference(dp->plums[pctx->plum_id]);
	replicator_for_each(plum, ctx, replicator_id, src_port);
}
