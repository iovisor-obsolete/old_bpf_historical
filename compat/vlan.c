/*
 * Copyright (c) 2007-2011 Nicira, Inc.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if_vlan.h>
#include <linux/skbuff.h>

#include "datapath.h"
#include "vlan.h"

#ifdef NEED_VLAN_FIELD
void vlan_copy_skb_tci(struct sk_buff *skb)
{
	OVS_CB(skb)->vlan_tci = 0;
}

u16 vlan_get_tci(struct sk_buff *skb)
{
	return OVS_CB(skb)->vlan_tci;
}

void vlan_set_tci(struct sk_buff *skb, u16 vlan_tci)
{
	OVS_CB(skb)->vlan_tci = vlan_tci;
}

bool vlan_tx_tag_present(struct sk_buff *skb)
{
	return OVS_CB(skb)->vlan_tci & VLAN_TAG_PRESENT;
}

u16 vlan_tx_tag_get(struct sk_buff *skb)
{
	return OVS_CB(skb)->vlan_tci & ~VLAN_TAG_PRESENT;
}

struct sk_buff *__vlan_hwaccel_put_tag(struct sk_buff *skb, u16 vlan_tci)
{
	OVS_CB(skb)->vlan_tci = vlan_tci | VLAN_TAG_PRESENT;
	return skb;
}
#endif /* NEED_VLAN_FIELD */

static struct sk_buff *vlan_reorder_header(struct sk_buff *skb)
{
        if (skb_cow(skb, skb_headroom(skb)) < 0)
                return NULL;
        memmove(skb->data - ETH_HLEN, skb->data - VLAN_ETH_HLEN, 2 * ETH_ALEN);
        skb->mac_header += VLAN_HLEN;
        return skb;
}

struct sk_buff *vlan_untag(struct sk_buff *skb)
{
        struct vlan_hdr *vhdr;
        u16 vlan_tci;

        if (unlikely(vlan_tx_tag_present(skb))) {
                /* vlan_tci is already set-up so leave this for another time */
                return skb;
        }

        skb = skb_share_check(skb, GFP_ATOMIC);
        if (unlikely(!skb))
                goto err_free;

        if (unlikely(!pskb_may_pull(skb, VLAN_HLEN)))
                goto err_free;

        vhdr = (struct vlan_hdr *) skb->data;
        vlan_tci = ntohs(vhdr->h_vlan_TCI);
        __vlan_hwaccel_put_tag(skb, skb->protocol, vlan_tci);

        skb_pull_rcsum(skb, VLAN_HLEN);
        vlan_set_encap_proto(skb, vhdr);

        skb = vlan_reorder_header(skb);
        if (unlikely(!skb))
                goto err_free;

        skb_reset_network_header(skb);
        skb_reset_transport_header(skb);
        skb_reset_mac_len(skb);

        return skb;

err_free:
        kfree_skb(skb);
        return NULL;
}
