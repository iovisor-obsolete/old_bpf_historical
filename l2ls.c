/*
 * Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <net/ethernet.h>
#include <linux/filter.h>
#include <linux/openvswitch.h>
#include <linux/ip.h>
#include <linux/in.h>
#include "bpf_api.h"

struct l2_table_key {
	uint8_t mac[ETHER_ADDR_LEN];
} __attribute__((aligned(8)));
#define STRUCTID_l2_table_key 0

struct l2_table_leaf {
	uint16_t port_id;
} __attribute__((aligned(8)));
#define STRUCTID_l2_table_leaf 1
#define TABLEID_l2_table 0

struct port_key {
	uint16_t port_id;
} __attribute__((aligned(8)));
#define STRUCTID_port_key 2

struct port_leaf {
	uint16_t vlan_id;
	uint32_t tunnel_id;
} __attribute__((aligned(8)));
#define STRUCTID_port_leaf 3
#define TABLEID_port_table 1

void bridge(struct bpf_context *pkt)
{
	struct port_key pkey = {};
	struct port_leaf *pleaf;
	struct l2_table_key l2key = {};
	struct l2_table_leaf *l2leaf;
	struct l2_table_leaf newl2leaf = {};

	if (pkt->vlan_tag) {
		if (bpf_pop_vlan(pkt))
			return;
	}

	if (bpf_load_bits(pkt, 6, l2key.mac, 6))
		return;
	l2leaf = bpf_table_lookup(pkt, TABLEID_l2_table, &l2key);
	if (!l2leaf || l2leaf->port_id != pkt->port_id) {
		newl2leaf.port_id = pkt->port_id;
		bpf_table_update(pkt, TABLEID_l2_table, &l2key, &newl2leaf);
	}

	if (bpf_load_bits(pkt, 0, l2key.mac, 6))
		return;
	if ((l2key.mac[0] & l2key.mac[1] & l2key.mac[2] & l2key.mac[3] &
	     l2key.mac[4] & l2key.mac[5]) == 0xff) {
		bpf_replicate(pkt, 1, pkt->port_id);
	} else {
		l2leaf = bpf_table_lookup(pkt, TABLEID_l2_table, &l2key);
		if (!l2leaf) {
			bpf_replicate(pkt, 1, pkt->port_id);
		} else {
			pkey.port_id = l2leaf->port_id;
			pleaf = bpf_table_lookup(pkt, TABLEID_port_table,
						 &pkey);

			if (pleaf && pleaf->vlan_id) {
				if (bpf_push_vlan(pkt, bpf_htons(ETH_P_8021Q), pleaf->vlan_id))
					return;
			}

			bpf_forward(pkt, l2leaf->port_id);
		}
	}

}

struct bpf_table bridge_tables[] = {
	{TABLEID_l2_table, BPF_TABLE_HASH, sizeof(struct l2_table_key),
	 sizeof(struct l2_table_leaf), 4096, 0}, // l2_table
	{TABLEID_port_table, BPF_TABLE_HASH, sizeof(struct port_key),
	 sizeof(struct port_leaf), 4096, 0}, // port_table
	{0, 0, 0, 0, 0, 0} // last table marker
};
