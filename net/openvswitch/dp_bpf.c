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
#include <linux/openvswitch.h>
#include <linux/if_vlan.h>
#include "datapath.h"

struct kmem_cache *plum_stack_cache;

struct genl_family dp_bpf_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_BPF_FAMILY,
	.version = OVS_BPF_VERSION,
	.maxattr = OVS_BPF_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
};

static const struct nla_policy bpf_policy[OVS_BPF_ATTR_MAX + 1] = {
	[OVS_BPF_ATTR_PLUM] = { .type = NLA_UNSPEC },
	[OVS_BPF_ATTR_PLUM_ID] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_PORT_ID] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_DEST_PLUM_ID] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_DEST_PORT_ID] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_TABLE_ID] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_KEY_OBJ] = { .type = NLA_UNSPEC },
	[OVS_BPF_ATTR_LEAF_OBJ] = { .type = NLA_UNSPEC },
	[OVS_BPF_ATTR_REPLICATOR_ID] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_PACKET] = { .type = NLA_UNSPEC },
	[OVS_BPF_ATTR_DIRECTION] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_FWD_PLUM_ID] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_ARG1] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_ARG2] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_ARG3] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_ARG4] = { .type = NLA_U32 },
	[OVS_BPF_ATTR_DISRUPTIVE] = { .type = NLA_U32 }
};

static struct sk_buff *gen_reply_u32(u32 pid, u32 value)
{
	struct sk_buff *skb;
	int ret;
	void *data;

	skb = genlmsg_new(nla_total_size(sizeof(u32)), GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	data = genlmsg_put(skb, pid, 0, &dp_bpf_genl_family, 0, 0);
	if (!data) {
		ret = -EMSGSIZE;
		goto error;
	}

	ret = nla_put_u32(skb, OVS_BPF_ATTR_UNSPEC, value);
	if (ret < 0)
		goto error;

	genlmsg_end(skb, data);

	return skb;

error:
	kfree_skb(skb);
	return ERR_PTR(ret);
}

/* Called with rcu_read_lock. */
static struct sk_buff *gen_reply_unspec(u32 pid, u32 len, void *ptr)
{
	struct sk_buff *skb;
	int ret;
	void *data;

	skb = genlmsg_new(nla_total_size(len), GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	data = genlmsg_put(skb, pid, 0, &dp_bpf_genl_family, 0, 0);
	if (!data) {
		ret = -EMSGSIZE;
		goto error;
	}

	ret = nla_put(skb, OVS_BPF_ATTR_UNSPEC, len, ptr);
	if (ret < 0)
		goto error;

	genlmsg_end(skb, data);

	return skb;

error:
	kfree_skb(skb);
	return ERR_PTR(ret);
}

static void reset_port_stats(struct plum *plum, u32 port_id)
{
	int i;
	struct pcpu_port_stats *stats;

	for_each_possible_cpu(i) {
		stats = per_cpu_ptr(plum->stats[port_id], i);
		u64_stats_update_begin(&stats->syncp);
		stats->rx_packets = 0;
		stats->rx_bytes = 0;
		stats->rx_mcast_packets = 0;
		stats->rx_mcast_bytes = 0;
		stats->tx_packets = 0;
		stats->tx_bytes = 0;
		stats->tx_mcast_packets = 0;
		stats->tx_mcast_bytes = 0;
		u64_stats_update_end(&stats->syncp);
	}
}

static int get_port_stats(struct plum *plum, u32 port_id,
			  struct ovs_bpf_port_stats *stats)
{
	int i;
	const struct pcpu_port_stats *pstats;
	struct pcpu_port_stats local_pstats;
	int start;

	if (!plum->stats[port_id])
		return -EINVAL;

	memset(stats, 0, sizeof(*stats));

	for_each_possible_cpu(i) {
		pstats = per_cpu_ptr(plum->stats[port_id], i);

		do {
			start = u64_stats_fetch_begin_bh(&pstats->syncp);
			local_pstats = *pstats;
		} while (u64_stats_fetch_retry_bh(&pstats->syncp, start));

		stats->rx_packets += local_pstats.rx_packets;
		stats->rx_bytes += local_pstats.rx_bytes;
		stats->rx_mcast_packets += local_pstats.rx_mcast_packets;
		stats->rx_mcast_bytes += local_pstats.rx_mcast_bytes;
		stats->tx_packets += local_pstats.tx_packets;
		stats->tx_bytes += local_pstats.tx_bytes;
		stats->tx_mcast_packets += local_pstats.tx_mcast_packets;
		stats->tx_mcast_bytes += local_pstats.tx_mcast_bytes;
	}

	return 0;
}

static int ovs_bpf_cmd_register_plum(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	int ret;
	u32 plum_id = -EINVAL;
	struct plum *plum, *old_plum = NULL;
	u32 upcall_pid;
	struct bpf_image *image;
	bool alloc_tbl = false;

	if (!a[OVS_BPF_ATTR_PLUM] || !a[OVS_BPF_ATTR_UPCALL_PID] ||
	    !a[OVS_BPF_ATTR_PLUM_ID])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	image = nla_data(a[OVS_BPF_ATTR_PLUM]);

	if (nla_len(a[OVS_BPF_ATTR_PLUM]) != sizeof(struct bpf_image)) {
		pr_err("unsupported plum size %d\n",
		       nla_len(a[OVS_BPF_ATTR_PLUM]));
		ret = -EINVAL;
		goto exit_unlock;
	}

	upcall_pid = nla_get_u32(a[OVS_BPF_ATTR_UPCALL_PID]);
	if (a[OVS_BPF_ATTR_DISRUPTIVE])
		alloc_tbl = !!nla_get_u32(a[OVS_BPF_ATTR_DISRUPTIVE]);

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (!plum_id) {
		for (plum_id = MIN_PLUM_ID;; plum_id++) {
			if (plum_id >= DP_MAX_PLUMS) {
				ret = -EFBIG;
				goto exit_unlock;
			}
			plum = ovsl_dereference(dp->plums[plum_id]);
			if (!plum)
				break;
		}
	} else {
		plum = ovsl_dereference(dp->plums[plum_id]);
		if (plum)
			old_plum = plum;
	}

	plum = bpf_dp_register_plum(image, old_plum, alloc_tbl);
	ret = PTR_ERR(plum);
	if (IS_ERR(plum))
		goto exit_unlock;

	plum->upcall_pid = upcall_pid;
	rcu_assign_pointer(dp->plums[plum_id], plum);

	if (old_plum)
		bpf_dp_unregister_plum(old_plum, alloc_tbl ? PLUM_TABLES : 0);

	reply = gen_reply_u32(info->snd_portid, plum_id);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

static int ovs_bpf_cmd_unregister_plum(struct sk_buff *skb,
				       struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	u32 plum_id;
	struct plum *plum;
	struct plum *dest_plum;
	u32 dest;
	int ret;
	int i;

	if (!a[OVS_BPF_ATTR_PLUM_ID])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = ovsl_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	for (i = 0; i < PLUM_MAX_PORTS; i++) {
		dest = atomic_read(&plum->ports[i]);
		if (dest) {
			dest_plum = ovsl_dereference(dp->plums[dest >> 16]);
			if (!dest_plum)
				continue;
			atomic_set(&dest_plum->ports[dest & 0xffff], 0);
		}
	}

	rcu_assign_pointer(dp->plums[plum_id], NULL);

	bpf_dp_unregister_plum(plum, PLUM_DATA | PLUM_TABLES);

	reply = gen_reply_u32(info->snd_portid, plum_id);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

static int validate_ports(struct datapath *dp, u32 plum_id, u32 port_id,
			  u32 dest_plum_id, u32 dest_port_id)
{
	if (plum_id >= DP_MAX_PLUMS || dest_plum_id >= DP_MAX_PLUMS) {
		pr_err("validate_ports(%d, %d, %d, %d): plum_id is too large",
		       plum_id, port_id, dest_plum_id, dest_port_id);
		return -EFBIG;
	} else if (MUX(plum_id, port_id) == 0 ||
		   MUX(dest_plum_id, dest_port_id) == 0 ||
		   plum_id == dest_plum_id) {
		pr_err("validate_ports(%d, %d, %d, %d): plum/port combination is invalid\n",
		       plum_id, port_id, dest_plum_id, dest_port_id);
		return -EINVAL;
	} else if (port_id >= PLUM_MAX_PORTS ||
		   dest_port_id >= PLUM_MAX_PORTS) {
		pr_err("validate_ports(%d, %d, %d, %d): port_id is too large\n",
		       plum_id, port_id, dest_plum_id, dest_port_id);
		return -EFBIG;
	}
	if (plum_id == 0) {
		struct vport *vport;
		vport = ovs_vport_ovsl_rcu(dp, port_id);
		if (!vport) {
			pr_err("validate_ports(%d, %d, %d, %d): vport doesn't exist\n",
			       plum_id, port_id, dest_plum_id, dest_port_id);
			return -EINVAL;
		}
	}
	if (dest_plum_id == 0) {
		struct vport *dest_vport;
		dest_vport = ovs_vport_ovsl_rcu(dp, dest_port_id);
		if (!dest_vport) {
			pr_err("validate_ports(%d, %d, %d, %d): vport doesn't exist\n",
			       plum_id, port_id, dest_plum_id, dest_port_id);
			return -EINVAL;
		}
	}

	return 0;
}

/* connect_ports(src_plum_id, src_port_id, dest_plum_id, dest_port_id)
 * establishes bi-directional virtual wire between two plums
 */
static int ovs_bpf_cmd_connect_ports(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	u32 plum_id, port_id, dest_plum_id, dest_port_id;
	struct plum *plum, *dest_plum;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_PORT_ID] ||
	    !a[OVS_BPF_ATTR_DEST_PLUM_ID] || !a[OVS_BPF_ATTR_DEST_PORT_ID])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	dest_plum_id = nla_get_u32(a[OVS_BPF_ATTR_DEST_PLUM_ID]);
	port_id = nla_get_u32(a[OVS_BPF_ATTR_PORT_ID]);
	dest_port_id = nla_get_u32(a[OVS_BPF_ATTR_DEST_PORT_ID]);

	ret = validate_ports(dp, plum_id, port_id, dest_plum_id, dest_port_id);
	if (ret != 0)
		goto exit_unlock;

	plum = ovsl_dereference(dp->plums[plum_id]);
	dest_plum = ovsl_dereference(dp->plums[dest_plum_id]);
	if (!plum || !dest_plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	if (atomic_read(&plum->ports[port_id]) != 0 ||
	    atomic_read(&dest_plum->ports[dest_port_id]) != 0) {
		ret = -EBUSY;
		goto exit_unlock;
	}

	if (!plum->stats[port_id]) {
		plum->stats[port_id] = alloc_percpu(struct pcpu_port_stats);
		if (!plum->stats[port_id]) {
			ret = -ENOMEM;
			goto exit_unlock;
		}
	} else {
		reset_port_stats(plum, port_id);
	}

	if (!dest_plum->stats[dest_port_id]) {
		dest_plum->stats[dest_port_id] =
			alloc_percpu(struct pcpu_port_stats);
		if (!dest_plum->stats[dest_port_id]) {
			ret = -ENOMEM;
			goto exit_unlock;
		}
	} else {
		reset_port_stats(dest_plum, dest_port_id);
	}

	atomic_set(&plum->ports[port_id], MUX(dest_plum_id, dest_port_id));
	atomic_set(&dest_plum->ports[dest_port_id], MUX(plum_id, port_id));
	smp_wmb();

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* disconnect_ports(src_plum_id, src_port_id, dest_plum_id, dest_port_id)
 * removes virtual wire between two plums
 */
static int ovs_bpf_cmd_disconnect_ports(struct sk_buff *skb,
					struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	u32 plum_id, port_id, dest_plum_id, dest_port_id;
	struct plum *plum, *dest_plum;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_PORT_ID] ||
	    !a[OVS_BPF_ATTR_DEST_PLUM_ID] || !a[OVS_BPF_ATTR_DEST_PORT_ID])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	dest_plum_id = nla_get_u32(a[OVS_BPF_ATTR_DEST_PLUM_ID]);
	port_id = nla_get_u32(a[OVS_BPF_ATTR_PORT_ID]);
	dest_port_id = nla_get_u32(a[OVS_BPF_ATTR_DEST_PORT_ID]);

	ret = validate_ports(dp, plum_id, port_id, dest_plum_id, dest_port_id);
	if (ret != 0)
		goto exit_unlock;

	plum = ovsl_dereference(dp->plums[plum_id]);
	dest_plum = ovsl_dereference(dp->plums[dest_plum_id]);

	if (plum)
		atomic_set(&plum->ports[port_id], 0);
	if (dest_plum)
		atomic_set(&dest_plum->ports[dest_port_id], 0);
	smp_wmb();

	/* leave the stats allocated until plum is freed */

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* update_table_element(plum_id, table_id, key, value) */
static int ovs_bpf_cmd_update_table_element(struct sk_buff *skb,
					    struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, table_id;
	char *key_data, *leaf_data;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_TABLE_ID] ||
	    !a[OVS_BPF_ATTR_KEY_OBJ] || !a[OVS_BPF_ATTR_LEAF_OBJ])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = ovsl_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	table_id = nla_get_u32(a[OVS_BPF_ATTR_TABLE_ID]);
	if (table_id >= plum->num_tables) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	key_data = nla_data(a[OVS_BPF_ATTR_KEY_OBJ]);
	leaf_data = nla_data(a[OVS_BPF_ATTR_LEAF_OBJ]);

	ret = bpf_dp_update_table_element(plum, table_id, key_data, leaf_data);

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* clear_table_elements(plum_id, table_id) */
static int ovs_bpf_cmd_clear_table_elements(struct sk_buff *skb,
					    struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, table_id;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_TABLE_ID])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = ovsl_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	table_id = nla_get_u32(a[OVS_BPF_ATTR_TABLE_ID]);
	if (table_id >= plum->num_tables) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	ret = bpf_dp_clear_table_elements(plum, table_id);

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* delete_table_element(plum_id, table_id, key) */
static int ovs_bpf_cmd_delete_table_element(struct sk_buff *skb,
					    struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, table_id;
	char *key_data;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_TABLE_ID] ||
	    !a[OVS_BPF_ATTR_KEY_OBJ])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = ovsl_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	table_id = nla_get_u32(a[OVS_BPF_ATTR_TABLE_ID]);
	if (table_id >= plum->num_tables) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	key_data = nla_data(a[OVS_BPF_ATTR_KEY_OBJ]);

	ret = bpf_dp_delete_table_element(plum, table_id, key_data);

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* read_table_element(plum_id, table_id, key) */
static int ovs_bpf_cmd_read_table_element(struct sk_buff *skb,
					  struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, table_id;
	char *key_data;
	void *elem_data;
	u32 elem_size;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_TABLE_ID] ||
	    !a[OVS_BPF_ATTR_KEY_OBJ])
		return -EINVAL;

	rcu_read_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = rcu_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	table_id = nla_get_u32(a[OVS_BPF_ATTR_TABLE_ID]);
	if (table_id >= plum->num_tables) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	key_data = nla_data(a[OVS_BPF_ATTR_KEY_OBJ]);

	elem_data = bpf_dp_read_table_element(plum, table_id, key_data,
					      &elem_size);
	if (IS_ERR(elem_data)) {
		ret = PTR_ERR(elem_data);
		goto exit_unlock;
	}

	reply = gen_reply_unspec(info->snd_portid, elem_size, elem_data);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	rcu_read_unlock();

	return ret;
}

/* read_table_elements(plum_id, table_id) via dumpit */
static int ovs_bpf_cmd_read_table_elements(struct sk_buff *skb,
					   struct netlink_callback *cb)
{
	struct nlattr *nla_plum_id, *nla_table_id;
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, table_id;
	long row, obj;
	void *data;
	void *elem_data;
	u32 elem_size;
	int ret = 0;

	nla_plum_id = nlmsg_find_attr(cb->nlh, GENL_HDRLEN +
				      sizeof(struct ovs_header),
				      OVS_BPF_ATTR_PLUM_ID);
	nla_table_id = nlmsg_find_attr(cb->nlh, GENL_HDRLEN +
				       sizeof(struct ovs_header),
				       OVS_BPF_ATTR_TABLE_ID);
	if (!nla_plum_id || !nla_table_id)
		return -EINVAL;

	rcu_read_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(nla_plum_id);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = rcu_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	table_id = nla_get_u32(nla_table_id);
	if (table_id >= plum->num_tables) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	for (;;) {
		row = cb->args[0];
		obj = cb->args[1];

		elem_data = bpf_dp_read_table_element_next(plum, table_id,
							   &row, &obj,
							   &elem_size);
		if (IS_ERR(elem_data)) {
			ret = PTR_ERR(elem_data);
			goto exit_unlock;
		}

		if (!elem_data)
			goto exit_unlock;

		data = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, 0,
				   &dp_bpf_genl_family, NLM_F_MULTI, 0);
		if (!data)
			goto exit_unlock;

		ret = nla_put(skb, OVS_BPF_ATTR_UNSPEC, elem_size, elem_data);
		if (ret < 0) {
			genlmsg_cancel(skb, data);
			ret = 0;
			goto exit_unlock;
		}

		genlmsg_end(skb, data);

		cb->args[0] = row;
		cb->args[1] = obj;
	}

exit_unlock:
	rcu_read_unlock();

	return ret < 0 ? ret : skb->len;
}

/* del_replicator(plum_id, replicator_id) */
static int ovs_bpf_cmd_del_replicator(struct sk_buff *skb,
				      struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, replicator_id;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_REPLICATOR_ID])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = ovsl_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	replicator_id = nla_get_u32(a[OVS_BPF_ATTR_REPLICATOR_ID]);
	if (replicator_id >= PLUM_MAX_REPLICATORS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	ret = bpf_dp_replicator_del_all(plum, replicator_id);

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* add_port_to_replicator(plum_id, replicator_id, port_id) */
static int ovs_bpf_cmd_add_port_to_replicator(struct sk_buff *skb,
					      struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, port_id, replicator_id;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_PORT_ID] ||
	    !a[OVS_BPF_ATTR_REPLICATOR_ID])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = ovsl_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	port_id = nla_get_u32(a[OVS_BPF_ATTR_PORT_ID]);
	if (port_id >= PLUM_MAX_PORTS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	replicator_id = nla_get_u32(a[OVS_BPF_ATTR_REPLICATOR_ID]);
	if (replicator_id >= PLUM_MAX_REPLICATORS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	ret = bpf_dp_replicator_add_port(plum, replicator_id, port_id);

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* del_port_from_replicator(plum_id, replicator_id, port_id) */
static int ovs_bpf_cmd_del_port_from_replicator(struct sk_buff *skb,
						struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, port_id, replicator_id;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_PORT_ID] ||
	    !a[OVS_BPF_ATTR_REPLICATOR_ID])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = ovsl_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	port_id = nla_get_u32(a[OVS_BPF_ATTR_PORT_ID]);
	if (port_id >= PLUM_MAX_PORTS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	replicator_id = nla_get_u32(a[OVS_BPF_ATTR_REPLICATOR_ID]);
	if (replicator_id >= PLUM_MAX_REPLICATORS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	ret = bpf_dp_replicator_del_port(plum, replicator_id, port_id);

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* channel_push(plum_id, port_id, fwd_plum_id, arg1/2/3/4, packet, direction) */
static int ovs_bpf_cmd_channel_push(struct sk_buff *skb,
				    struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	u32 plum_id, port_id, dir, fwd_plum_id, arg1, arg2, arg3, arg4;
	struct sk_buff *packet;
	struct ethhdr *eth;
	struct plum *plum;
	int len;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_PORT_ID] ||
	    !a[OVS_BPF_ATTR_FWD_PLUM_ID] || !a[OVS_BPF_ATTR_ARG1] ||
	    !a[OVS_BPF_ATTR_ARG2] || !a[OVS_BPF_ATTR_ARG3] ||
	    !a[OVS_BPF_ATTR_ARG4] || !a[OVS_BPF_ATTR_PACKET] ||
	    !a[OVS_BPF_ATTR_DIRECTION])
		return -EINVAL;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = ovsl_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	port_id = nla_get_u32(a[OVS_BPF_ATTR_PORT_ID]);
	if (port_id >= PLUM_MAX_PORTS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	fwd_plum_id = nla_get_u32(a[OVS_BPF_ATTR_FWD_PLUM_ID]);
	arg1 = nla_get_u32(a[OVS_BPF_ATTR_ARG1]);
	arg2 = nla_get_u32(a[OVS_BPF_ATTR_ARG2]);
	arg3 = nla_get_u32(a[OVS_BPF_ATTR_ARG3]);
	arg4 = nla_get_u32(a[OVS_BPF_ATTR_ARG4]);
	dir = nla_get_u32(a[OVS_BPF_ATTR_DIRECTION]);

	len = nla_len(a[OVS_BPF_ATTR_PACKET]);
	packet = __dev_alloc_skb(NET_IP_ALIGN + len, GFP_KERNEL);
	if (!packet) {
		ret = -ENOMEM;
		goto exit_unlock;
	}
	skb_reserve(packet, NET_IP_ALIGN);

	nla_memcpy(__skb_put(packet, len), a[OVS_BPF_ATTR_PACKET], len);

	skb_reset_mac_header(packet);

	eth = eth_hdr(packet);
	if (eth->h_proto >= htons(ETH_P_802_3_MIN))
		packet->protocol = eth->h_proto;
	else
		packet->protocol = htons(ETH_P_802_2);

	/* if inband header exists, nh offset will be reset later */
	if (packet->protocol == htons(ETH_P_8021Q))
		skb_set_network_header(packet, VLAN_ETH_HLEN);
	else
		skb_set_network_header(packet, ETH_HLEN);

	ret = bpf_dp_channel_push_on_plum(dp, plum_id, port_id, fwd_plum_id,
					  arg1, arg2, arg3, arg4, packet, dir);

	reply = gen_reply_u32(info->snd_portid, ret);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	ovs_unlock();

	return ret;
}

/* read_port_stats(plum_id, port_id) */
static int ovs_bpf_cmd_read_port_stats(struct sk_buff *skb,
				       struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct datapath *dp;
	struct plum *plum;
	u32 plum_id, port_id;
	struct ovs_bpf_port_stats stats;
	int ret;

	if (!a[OVS_BPF_ATTR_PLUM_ID] || !a[OVS_BPF_ATTR_PORT_ID])
		return -EINVAL;

	rcu_read_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	plum_id = nla_get_u32(a[OVS_BPF_ATTR_PLUM_ID]);
	if (plum_id >= DP_MAX_PLUMS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	plum = rcu_dereference(dp->plums[plum_id]);
	if (!plum) {
		ret = -EINVAL;
		goto exit_unlock;
	}

	port_id = nla_get_u32(a[OVS_BPF_ATTR_PORT_ID]);
	if (port_id >= PLUM_MAX_PORTS) {
		ret = -EFBIG;
		goto exit_unlock;
	}

	ret = get_port_stats(plum, port_id, &stats);
	if (ret < 0)
		goto exit_unlock;

	reply = gen_reply_unspec(info->snd_portid, sizeof(stats), &stats);

	if (IS_ERR(reply)) {
		ret = PTR_ERR(reply);
		goto exit_unlock;
	}

	ret = genlmsg_unicast(sock_net(skb->sk), reply, info->snd_portid);

exit_unlock:
	rcu_read_unlock();

	return ret;
}

struct genl_ops dp_bpf_genl_ops[] = {
	{ .cmd = OVS_BPF_CMD_REGISTER_PLUM,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_register_plum
	},
	{ .cmd = OVS_BPF_CMD_UNREGISTER_PLUM,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_unregister_plum
	},
	{ .cmd = OVS_BPF_CMD_CONNECT_PORTS,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_connect_ports
	},
	{ .cmd = OVS_BPF_CMD_DISCONNECT_PORTS,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_disconnect_ports
	},
	{ .cmd = OVS_BPF_CMD_CLEAR_TABLE_ELEMENTS,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_clear_table_elements
	},
	{ .cmd = OVS_BPF_CMD_DELETE_TABLE_ELEMENT,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_delete_table_element
	},
	{ .cmd = OVS_BPF_CMD_READ_TABLE_ELEMENT,
	  .flags = 0,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_read_table_element,
	  .dumpit = ovs_bpf_cmd_read_table_elements
	},
	{ .cmd = OVS_BPF_CMD_UPDATE_TABLE_ELEMENT,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_update_table_element
	},
	{ .cmd = OVS_BPF_CMD_DEL_REPLICATOR,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_del_replicator
	},
	{ .cmd = OVS_BPF_CMD_ADD_PORT_TO_REPLICATOR,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_add_port_to_replicator
	},
	{ .cmd = OVS_BPF_CMD_DEL_PORT_FROM_REPLICATOR,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_del_port_from_replicator
	},
	{ .cmd = OVS_BPF_CMD_CHANNEL_PUSH,
	  .flags = GENL_ADMIN_PERM,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_channel_push
	},
	{ .cmd = OVS_BPF_CMD_READ_PORT_STATS,
	  .flags = 0,
	  .policy = bpf_policy,
	  .doit = ovs_bpf_cmd_read_port_stats
	},
};

/* Initializes the BPF module.
 * Returns zero if successful or a negative error code.
 */
int ovs_bpf_init(void)
{
	plum_stack_cache = kmem_cache_create("plum_stack",
					     sizeof(struct plum_stack_frame), 0,
					     0, NULL);
	if (plum_stack_cache == NULL)
		return -ENOMEM;

	return 0;
}

/* Uninitializes the BPF module. */
void ovs_bpf_exit(void)
{
	kmem_cache_destroy(plum_stack_cache);
}
