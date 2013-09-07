#include <stdint.h>
#include <linux/filter.h>
#include <linux/openvswitch.h>

#include "bpf_api.h"

#define ENCAP_GRE   1
#define ENCAP_VXLAN 2

#define PORT_GRE    1
#define PORT_VXLAN  2

struct port2tun_key {
	uint16_t port_id;
} __attribute__((aligned(8)));
#define STRUCTID_port2tun_key 1

struct port2tun_leaf {
	uint8_t encap_type;
	uint32_t tunnel_id;
	uint32_t src_ip;
	uint32_t dst_ip;
} __attribute__((aligned(8)));
#define STRUCTID_port2tun_leaf 2
#define TABLEID_port2tun_table 0

struct tun2port_key {
	uint8_t encap_type;
	uint32_t tunnel_id;
} __attribute__((aligned(8)));
#define STRUCTID_tun2port_key 3

struct tun2port_leaf {
	uint16_t port_id;
} __attribute__((aligned(8)));
#define STRUCTID_tun2port_leaf 4
#define TABLEID_tun2port_table 1

void tunnel(struct bpf_context *pkt)
{
	struct port2tun_key p2t_key = {};
	struct port2tun_leaf *p2t_leaf;
	struct tun2port_key t2p_key = {};
	struct tun2port_leaf *t2p_leaf;

	if (pkt->port_id != PORT_GRE && pkt->port_id != PORT_VXLAN) {
		p2t_key.port_id = pkt->port_id;
		p2t_leaf = bpf_table_lookup(pkt, TABLEID_port2tun_table,
					    &p2t_key);
		if (!p2t_leaf)
			return;
		pkt->tun_key.tun_id = p2t_leaf->tunnel_id;
		pkt->tun_key.src_ip = p2t_leaf->src_ip;
		pkt->tun_key.dst_ip = p2t_leaf->dst_ip;
		pkt->tun_key.tos = 0;
		pkt->tun_key.ttl = 64;
		bpf_forward(pkt, p2t_leaf->encap_type);
	} else {
		t2p_key.encap_type = (pkt->port_id == PORT_GRE) ? ENCAP_GRE :
				     ENCAP_VXLAN;
		t2p_key.tunnel_id = pkt->tun_key.tun_id;
		pkt->tun_key.dst_ip = 0;
		t2p_leaf = bpf_table_lookup(pkt, TABLEID_tun2port_table,
					    &t2p_key);

		if (!t2p_leaf)
			return;
		bpf_forward(pkt, t2p_leaf->port_id);
	}
}


struct bpf_table tunnel_tables[] = {
	{TABLEID_port2tun_table, BPF_TABLE_HASH, sizeof(struct port2tun_key),
	 sizeof(struct port2tun_leaf), 4096, 0},
	{TABLEID_tun2port_table, BPF_TABLE_HASH, sizeof(struct tun2port_key),
	 sizeof(struct tun2port_leaf), 4096, 0},
	{0, 0, 0, 0, 0, 0} // last table marker
};
