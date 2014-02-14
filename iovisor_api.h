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

#define MAX_DUMP_BUF_SIZE 0xFFffff

typedef struct {
	uint8_t mac[ETHER_ADDR_LEN];
} __attribute__((aligned(8))) l2_key;

typedef struct {
	uint16_t port_id;
} __attribute__((aligned(8))) l2_config;

typedef struct {
	uint16_t port_id;
} __attribute__((aligned(8))) port_key;

typedef struct {
	uint16_t vlan_id;
	uint32_t tunnel_id;
} __attribute__((aligned(8))) port_config;

typedef struct {
	uint32_t tunnel_id;
} __attribute__((aligned(8))) tunnel_key;

typedef struct {
	uint8_t encap_type;
	uint32_t tunnel_key;
	uint8_t add_dot1q;
	uint16_t dot1q_vlan;
	uint64_t src_mac;
	uint64_t dest_mac;
	uint32_t src_ip;
	uint32_t dest_ip;
	uint8_t port_id;
} __attribute__((aligned(8))) tunnel_config;

typedef struct {
	uint8_t index;
} __attribute__((aligned(8))) config_key;

typedef struct {
	uint8_t fabric_port;
} __attribute__((aligned(8))) config_leaf;

typedef struct {
	uint8_t encap_type;
	uint32_t tunnel_key;
	uint32_t src_ip;
} __attribute__((aligned(8))) fabric_key;

typedef struct {
	uint32_t tunnel_id;
} __attribute__((aligned(8))) fabric_config;

typedef struct {
        uint16_t port_id;
} __attribute__((aligned(8))) port2tun_key;

typedef struct {
        uint8_t encap_type;
        uint32_t tunnel_id;
        uint32_t src_ip;
        uint32_t dst_ip;
} __attribute__((aligned(8))) port2tun_leaf;

typedef struct {
        uint8_t encap_type;
        uint32_t tunnel_id;
} __attribute__((aligned(8))) tun2port_key;

typedef struct {
        uint16_t port_id;
} __attribute__((aligned(8))) tun2port_leaf;

typedef struct {
	uint32_t plen;
	uint32_t prefix;
} rtable_key;

typedef struct {
	uint16_t port_id;
} __attribute__((aligned(8))) rtable_leaf;

int init_iovisor(void);
int lookup_port(const char *name, int *portno);
int add_port(const char *name, int *portno, int vport_type);
int register_plum(int *plum_id, struct bpf_insn insns[], uint32_t insns_sz,
		  unsigned int tables[], uint32_t tables_sz);
int connect_ports(int plum_id, int port_id, int dest_plum_id, int dest_port_id);
int add_replicator_port(int plum_id, int handle, int port_id);
int clear_elements(int plum_id, uint32_t table_id);
int delete_element(int plum_id, uint32_t table_id, void *key, int key_size);
void *read_element(int plum_id, uint32_t table_id, void *key, int key_size,
		   int *leaf_size);
int dump_element(int plum_id, uint32_t table_id, uint8_t *read_buf,
		 int *read_sz);
int update_element(int plum_id, uint32_t table_id, void *key, int key_size,
		   void *leaf, int leaf_size);
int del_replicator_port(int plum_id, int handle, int port_id);
int delete_replicator(int plum_id, int handle);
int disconnect_ports(int plum_id, int port_id, int dest_plum_id,
		     int dest_port_id);
int del_port(int portno);
int unregister_plum(int plum_id);
int reset_iovisor(void);
typedef void (*channel_handler_t)(uint8_t *packet, uint32_t size);
void register_channel_handler(channel_handler_t handler);
int channel_push(uint32_t plum_id, uint32_t port_id, uint8_t *packet,
                 uint32_t len);
int read_port_stats(int plum_id, uint32_t port_id,
		    struct ovs_bpf_port_stats *stats);
