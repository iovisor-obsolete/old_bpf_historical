#ifndef __NET_VXLAN_WRAPPER_H
#define __NET_VXLAN_WRAPPER_H  1

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/udp.h>

struct vxlan_sock;
typedef void (vxlan_rcv_t)(struct vxlan_sock *vs, struct sk_buff *skb, __be32 key);

/* per UDP socket information */
struct vxlan_sock {
	struct hlist_node hlist;
	vxlan_rcv_t	 *rcv;
	void		 *data;
	struct work_struct del_work;
	struct socket	 *sock;
	struct rcu_head	  rcu;
};

struct vxlan_sock *vxlan_sock_add(struct net *net, __be16 port,
				  vxlan_rcv_t *rcv, void *data,
				  bool no_share, bool);

void vxlan_sock_release(struct vxlan_sock *vs);

int vxlan_xmit_skb(struct vxlan_sock *vs,
		   struct rtable *rt, struct sk_buff *skb,
		   __be32 src, __be32 dst, __u8 tos, __u8 ttl, __be16 df,
		   __be16 src_port, __be16 dst_port, __be32 vni);

__be16 vxlan_src_port(__u16 port_min, __u16 port_max, struct sk_buff *skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
static inline void __inet_get_local_port_range(int *low, int *high)
{
	inet_get_local_port_range(low, high);
}
#define inet_get_local_port_range(A,B,C) __inet_get_local_port_range(B,C)
#endif

#endif
