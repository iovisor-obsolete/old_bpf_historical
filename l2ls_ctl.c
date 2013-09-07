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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/openvswitch.h>
#include <linux/filter.h>
#include "iovisor_api.h"

#include "l2ls_bpf.h"
#include "tunnel_port_bpf.h"

#define PORT_NAME_GRE     "port-gre"
#define PORT_NAME_VXLAN   "port-vxlan"
#define TUN_PORT_RESERVED 2
#define TUN_PORT_SHIFT    500

extern char *ether_ntoa_r(void *ptr, char *__buf);
extern void *ether_aton_r(char *__asc, void *ptr);

struct command
{
        int             nargs;
        const char      *name;
        int             (*func)(int argc, char *const* argv);
        const char      *help;
};

static void help();

static int addbr(int argc, char *const* argv)
{
	int ret;
	int tunnel_plum_id = 0, bridge_plum_id = 0;

	ret = register_plum(&tunnel_plum_id, bpf_insns_tunnel,
			    sizeof(bpf_insns_tunnel), bpf_tunnel_tables,
			    sizeof(bpf_tunnel_tables));
	if (ret) {
		printf("register_plum(tun) failed: %s\n", strerror(-ret));
		return ret;
	}

	if (tunnel_plum_id != 1) {
		printf("register_plum(tun) failed: plum_id %d\n", tunnel_plum_id);
		unregister_plum(tunnel_plum_id);
		return -1;
	}

	ret = register_plum(&bridge_plum_id, bpf_insns_bridge,
			    sizeof(bpf_insns_bridge),
			    bpf_bridge_tables, sizeof(bpf_bridge_tables));
	if (ret) {
		printf("register_plum(bridge) failed: %s\n", strerror(-ret));
		return ret;
	}

	if (bridge_plum_id != 2) {
		printf("register_plum(bridge) failed: plum_id %d\n", bridge_plum_id);
		unregister_plum(bridge_plum_id);
		return -1;
	}

	return 0;
}

static int delbr(int argc, char *const* argv)
{
	int ret;
	int plum_id = 2;

	ret = unregister_plum(plum_id);
	if (ret) {
		printf("unregister_plum(2) failed: %s\n", strerror(-ret));
		//ignore error
	}

	plum_id = 1;
	ret = unregister_plum(plum_id);
	if (ret) {
		printf("unregister_plum(1) failed: %s\n", strerror(-ret));
		//ignore error
	}

	ret = reset_iovisor();
	if (ret) {
		printf("rest iovisor failed: %s\n", strerror(-ret));
		//ignore error
	}

	return 0;
}

static int addtun(int argc, char *const* argv)
{
	int ret;
	int encap_type;
	int vport_type;
	struct in_addr remote;
	uint32_t remote_ip;
	uint32_t tunnel_id = 0;
	const char *dev_name;
	int portno = 0;
	int tun_plum_id = 1;
	int br_plum_id = 2;
	port2tun_key p2t_key = {};
	port2tun_leaf p2t_leaf = {};
	tun2port_key t2p_key = {};
	tun2port_leaf t2p_leaf = {};

	if (argc < 3) {
		help();
		return -1;
	}

	if (!strncmp(argv[1], "gre", 3)) {
		encap_type = 1;
		dev_name = PORT_NAME_GRE;
		vport_type = OVS_VPORT_TYPE_GRE;
	} else if (!strncmp(argv[1], "vxlan", 5)) {
		encap_type = 2;
		dev_name = PORT_NAME_VXLAN;
		vport_type = OVS_VPORT_TYPE_VXLAN;
	} else {
		fprintf(stderr, "Invalid tunnel type [%s]\n", argv[1]);
		return -1;
	}

	if (inet_aton(argv[2], &remote) == 0) {
		fprintf(stderr, "Invalid remote IP [%s]\n", argv[2]);
		return -1;
	}
	remote_ip = ntohl(remote.s_addr);

	if (argc >= 4) {
		tunnel_id = strtoul(argv[3], NULL, 0);
		if (tunnel_id > 10) {
			fprintf(stderr, "Tunnel id must be between 1 and 10\n");
			return -1;
		}
	}

	ret = lookup_port(argv[1], &portno);
	if (!portno) {
		/* create tun vport only once */
		ret = add_port(dev_name, &portno, vport_type);
		if (ret) {
			printf("add_port(%s) failed: %s\n", dev_name, strerror(-ret));
			return ret;
		}
		printf("tun port %d\n", portno);

		ret = connect_ports(0, portno, tun_plum_id, encap_type);
		if (ret) {
			printf("connect_ports() failed: %s\n", strerror(-ret));
			return ret;
		}
	}

	/* each tunnel uses one port between tunnel and bridge plumlets */
        ret = connect_ports(tun_plum_id, portno + TUN_PORT_RESERVED, br_plum_id,
			    tunnel_id + TUN_PORT_SHIFT);
	if (ret) {
		printf("connect_ports() failed: %s\n", strerror(-ret));
		return ret;
	}

        ret = add_replicator_port(br_plum_id, 1, tunnel_id + TUN_PORT_SHIFT);
	if (ret) {
		printf("add_replicator_port() failed: %s\n", strerror(-ret));
		return ret;
	}

	p2t_key.port_id = portno + TUN_PORT_RESERVED;
	p2t_leaf.encap_type = encap_type;
	p2t_leaf.tunnel_id = tunnel_id;
	p2t_leaf.src_ip = 0;
	p2t_leaf.dst_ip = remote_ip;
	ret = update_element(tun_plum_id, 0, &p2t_key, sizeof(p2t_key),
			     &p2t_leaf, sizeof(p2t_leaf));
	if (ret) {
		printf("update_element() failed: %s\n", strerror(-ret));
		return ret;
	}

	t2p_key.encap_type = encap_type;
	t2p_key.tunnel_id = tunnel_id;
	t2p_leaf.port_id = portno + TUN_PORT_RESERVED;
	ret = update_element(tun_plum_id, 1, &t2p_key, sizeof(t2p_key),
			     &t2p_leaf, sizeof(t2p_leaf));
	if (ret) {
		printf("update_element() failed: %s\n", strerror(-ret));
		return ret;
	}
}

static int addmac(int argc, char *const* argv)
{
	int ret;
	int plum_id = 2;
	l2_key l2key = {};
	l2_config l2config = {};
	uint8_t mac[ETHER_ADDR_LEN];
	int portno = atoi(argv[2]);

	ether_aton_r(argv[1], l2key.mac);
	l2config.port_id = portno;
	ret = update_element(plum_id, 0, &l2key, sizeof(l2key), &l2config,
			     sizeof(l2config));
	if (ret) {
		printf("update_element() failed: %s\n", strerror(-ret));
		return ret;
	}

	uint64_t i;
	memset(&l2key, 0, sizeof(l2key));
	for (i = 1; 1/* TEST only*/ && i <= 1004090; i++) {
		memcpy(l2key.mac, &i, ETHER_ADDR_LEN);
		l2config.port_id = 99;
		ret = update_element(plum_id, 0, &l2key, sizeof(l2key), &l2config,
				     sizeof(l2config));
		if (ret) {
			printf("update_element() failed: %s\n", strerror(-ret));
			return ret;
		}
	}

	return 0;
}

static int delmac(int argc, char *const* argv)
{
	int ret;
	int plum_id = 2;
	l2_key l2key = {};
	uint8_t mac[ETHER_ADDR_LEN];

	ether_aton_r(argv[1], l2key.mac);
	ret = delete_element(plum_id, 0, &l2key, sizeof(l2key));
	if (ret) {
		printf("delete_element() failed: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}

static void show_stats(int port_id)
{
	struct ovs_bpf_port_stats stats;
	int plum_id = 2;
	int ret;

	ret = read_port_stats(plum_id, port_id, &stats);
	if (ret)
		return;
	printf(" packets received            %lld\n", stats.rx_packets);
	printf(" bytes received              %lld\n", stats.rx_bytes);
	printf(" multicast pkts received     %lld\n", stats.rx_mcast_packets);
	printf(" multicast bytes received    %lld\n", stats.rx_mcast_bytes);
	printf(" packets transmitted         %lld\n", stats.tx_packets);
	printf(" bytes transmitted           %lld\n", stats.tx_bytes);
	printf(" multicast pkts transmitted  %lld\n", stats.tx_mcast_packets);
	printf(" multicast bytes transmitted %lld\n", stats.tx_mcast_bytes);
}
static int showmac(int argc, char *const* argv)
{
	int plum_id = 2;
	l2_key l2key = {};
	uint8_t mac[ETHER_ADDR_LEN];
	uint8_t *read, *curr;
	l2_key *l2k;
	l2_config *l2c;
	int len = 0;
	int count;
	char buf[128];
	uint32_t hit;

	if (argc > 1) {
		ether_aton_r(argv[1], l2key.mac);
		read = read_element(plum_id, 0, &l2key, sizeof(l2key), &len);
		if (len == sizeof(int) + sizeof(*l2k) + sizeof(*l2c)) {
			hit = *(int *)read;
			l2k = (l2_key *)(read + sizeof(int));
			l2c = (l2_config *)(read + sizeof(int) + sizeof(*l2k));
			printf("MAC %s Port %d hit_cnt %u\n",
			       ether_ntoa_r(&l2k->mac, buf),
			       l2c->port_id, hit);
		}
	} else {
		read = malloc(MAX_DUMP_BUF_SIZE);
		if (!read)
			return -1;
		if (dump_element(plum_id, 0, read, &len) < 0) {
			free(read);
			return -1;
		}
		if (len == 0) {
			free(read);
			return 0;
		}
		curr = read;
		while (len) {
			hit = *(int *)curr;
			l2k = (l2_key *)(curr + sizeof(int));
			l2c = (l2_config *)(curr + sizeof(int) + sizeof(*l2k));
			printf("MAC %s Port %d hit_cnt %u\n",
			       ether_ntoa_r(&l2k->mac, buf),
			       l2c->port_id, hit);
			show_stats(l2c->port_id);
			curr = curr + sizeof(int) + sizeof(*l2k) + sizeof(*l2c);
			len -= sizeof(int) + sizeof(*l2k) + sizeof(*l2c);
		}
		free(read);
	}

	return 0;
}

static int clearmac(int argc, char *const* argv)
{
	int ret;
	int plum_id = 2;

	ret = clear_elements(plum_id, 0);
	if (ret) {
		printf("clear_elements() failed: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}

static int addif(int argc, char *const* argv)
{
	int ret;
	int plum_id = 2;
	int portno = 0;
	port_key pkey = {};
	port_config pconfig = {};

	ret = lookup_port(argv[1], &portno);
	if (ret < 0) {
		printf("addif: lookup_port(%s) failed: %s\n", argv[1], strerror(-ret));
		return ret;
	}

	if (portno) {
		printf("addif: lookup_port(%s) port %d exist\n", argv[1], portno);
		return 0;
	}

	ret = add_port(argv[1], &portno, OVS_VPORT_TYPE_NETDEV);
	if (ret) {
		printf("add_port(%s) failed: %s\n", argv[1], strerror(-ret));
		return ret;
	}
	printf("addif(%s) port %d\n", argv[1], portno);

	pkey.port_id = portno;
	pconfig.vlan_id = (argc > 2) ? atoi(argv[2]) : 0;
	pconfig.tunnel_id = 0;
	ret = update_element(plum_id, 1, &pkey, sizeof(pkey), &pconfig, sizeof(pconfig));
	if (ret) {
		printf("update_element() failed: %s\n", strerror(-ret));
		return ret;
	}

	ret = connect_ports(0, portno, plum_id, portno);
	if (ret) {
		printf("connect_ports() failed: %s\n", strerror(-ret));
		return ret;
	}

	ret = add_replicator_port(plum_id, 1, portno);
	if (ret) {
		printf("add_replicator_port() failed: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}

static int delif(int argc, char *const* argv)
{
	int ret;
	int portno = 0;
	int plum_id = 2;

	ret = lookup_port(argv[1], &portno);
	if (ret < 0) {
		printf("delif: lookup_port(%s) failed: %s\n", argv[1], strerror(-ret));
		return ret;
	}

	if (portno == 0) {
		printf("delif: lookup_port(%s) returns 0, port doesnt exist\n",
		       argv[1]);
		return 0;
	}

	ret = del_replicator_port(plum_id, 1, portno);
	if (ret) {
		printf("del_replicator_port() failed: %s\n", strerror(-ret));
		//ignore error
	}

	ret = disconnect_ports(0, portno, plum_id, portno);
	if (ret) {
		printf("disconnect_ports() failed: %s\n", strerror(-ret));
		//ignore error
	}

	ret = del_port(portno);
	if (ret) {
		printf("del_port() failed: %s\n", strerror(-ret));
		//ignore error
	}

	return 0;
}

static const struct command commands[] = {
	{ 0, "addbr", addbr, "\t\t\tadd bridge" },
	{ 0, "delbr", delbr, "\t\t\tdelete bridge" },
	{ 1, "addif", addif, "<device> [vlan-id]\tadd interface to bridge"},
	{ 1, "delif", delif, "<device> [vlan-id]\tdelete interface from bridge" },
	{ 2, "addtun", addtun, "<gre|vxlan> <remote-ip> [tun-id]\tadd tunnel to bridge"},
	{ 2, "addmac", addmac, "<mac-address> <port-id>\tadd MAC to bridge"},
	{ 1, "delmac", delmac, "<mac-address>\tdelete MAC from bridge"},
	{ 0, "showmac", showmac, "[mac-address]\tDisplay bridge MAC table"},
	{ 0, "clearmac", clearmac, "\t\t\tClear bridge MAC table"}
};

static const struct command *command_lookup(const char *cmd)
{
	int i;

	for (i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
		if (!strcmp(cmd, commands[i].name))
			return &commands[i];
	}

	return NULL;
}

static void command_helpall(void)
{
	int i;

	for (i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
		printf("\t%-10s\t%s\n", commands[i].name, commands[i].help);
	}
}

static void help()
{
	printf("Usage: l2ls-ctl [commands]\n");
	printf("commands:\n");
	command_helpall();
}

int main(int argc, char *argv[])
{
	const struct command *cmd;
	int ret;

	if (argc < 2)
		goto help;

	ret = init_iovisor();
	if (ret) {
		printf("init_iovisor() failed: %s\n", strerror(-ret));
		return -1;
	}

	argc --;
	argv ++;
	if ((cmd = command_lookup(*argv)) == NULL) {
		fprintf(stderr, "Invalid command [%s]\n", argv[0]);
		goto help;
        }

        if (argc < cmd->nargs + 1) {
                fprintf(stderr, "Incorrect number of arguments for command\n");
                fprintf(stderr, "Usage: brctl %s %s\n", cmd->name, cmd->help);
                return -1;
        }

        return cmd->func(argc, argv);

help:
	help();
	return -1;
}
