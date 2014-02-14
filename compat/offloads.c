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
#include <linux/if_vlan.h>
#include <net/ip_tunnels.h>
#include "datapath.h"
#include "gso.h"

int handle_offloads(struct sk_buff *skb, u32 flags)
{
	skb_reset_inner_headers(skb);
	OVS_GSO_CB(skb)->encapsulation = 1;

	return 0;
}

/* perform segment and checksum if offloads are set for the inner packet
 * Note: No GSO hack for over MTU non-GSO packet.
 */
int offload_send(struct vport *vport, struct sk_buff *skb)
{
	int err;
	int tnl_nh_off, tnl_th_off, tnl_hlen;
	struct sk_buff *nskb, *orig_skb = NULL;
	struct iphdr *ih;
	struct udphdr *uh;

	if (!OVS_GSO_CB(skb)->encapsulation ||
	    (!skb_is_gso(skb) && skb->ip_summed != CHECKSUM_PARTIAL))
		return ovs_vport_send(vport, skb);

	tnl_nh_off = skb_network_offset(skb); /* set by push_header */
	tnl_th_off = skb_transport_offset(skb); /* set by push_header */
	tnl_hlen = skb_inner_mac_offset(skb); /* set by handle_offloads */

	__skb_pull(skb, tnl_hlen);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, skb_inner_network_offset(skb));
	skb->mac_len = skb_inner_network_offset(skb);

	if (skb_is_gso(skb)) {
		nskb = skb_gso_segment(skb, 0);
		if (IS_ERR(nskb)) {
			err = PTR_ERR(nskb);
			goto error;
		}

		skb_push(skb, tnl_hlen);
		orig_skb = skb;
		skb = nskb;
	} else if (skb->ip_summed == CHECKSUM_PARTIAL) {
		err = skb_linearize(skb);
		if (unlikely(err))
			goto error;

		err = skb_checksum_help(skb);
		if (unlikely(err))
			goto error;
	}

	while (skb) {
		skb_push(skb, tnl_hlen);
		if (orig_skb)
			skb_copy_to_linear_data(skb, orig_skb->data, tnl_hlen);
		skb_reset_mac_header(skb);
		skb->mac_len = tnl_nh_off;
		skb_set_network_header(skb, tnl_nh_off);
		skb_set_transport_header(skb, tnl_th_off);

		ih = ip_hdr(skb);
		ih->tot_len = htons(skb->len - skb_network_offset(skb));
		ih->check = 0;
		ih->check = ip_fast_csum(skb_network_header(skb), ih->ihl);
		if (ih->protocol == IPPROTO_UDP) {
			uh = udp_hdr(skb);
			uh->len = htons(skb->len - skb_transport_offset(skb));
		}

		nskb = skb->next;
		skb->next = NULL;

		ovs_vport_send(vport, skb);
		skb = nskb;
	}

	consume_skb(orig_skb);
	return 0;

error:
	kfree_skb(skb);
	return err;
}
