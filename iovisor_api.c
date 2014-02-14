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
#include <inttypes.h>
#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <pthread.h>
#include <linux/openvswitch.h>
#include <linux/filter.h>

#include "iovisor_api.h"

struct mnl_socket *sock;
unsigned int portid;
struct mnl_socket *ch_sock;
unsigned int ch_portid;
int dp_family_id;
int vport_family_id;
int pe_family_id;
int dp_ifindex;

pthread_t upcall_thread_id;

static int family_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case CTRL_ATTR_FAMILY_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int family_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	int *family_id = data;
	struct nlattr *tb[CTRL_ATTR_MAX+1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);

	ret = mnl_attr_parse(nlh, sizeof(*genl), family_attr_cb, tb);
	if (ret <= MNL_CB_STOP) {
		return ret;
	}
	if (tb[CTRL_ATTR_FAMILY_ID]) {
		*family_id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
	}

	return MNL_CB_OK;
}

static int genl_lookup_family(const char *name, int *family_id)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct mnl_socket *nl;
	unsigned int seq, portid;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = CTRL_CMD_GETFAMILY;
	genl->version = 1;

	mnl_attr_put_u32(nlh, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL);
	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, name);

	nl = mnl_socket_open(NETLINK_GENERIC);
	if (nl == NULL) {
		return -errno;
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		return -errno;
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, family_cb, family_id);
		if (ret <= MNL_CB_STOP) {
			break;
		}
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}
	mnl_socket_close(nl);

	return ret;
}

static int dp_new_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	int *ifindex = data;
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct ovs_header *ovs;

	ovs = mnl_nlmsg_get_payload_offset(nlh, sizeof(*genl));
	*ifindex = ovs->dp_ifindex;
	/* printf("dp_ifindex %d\n", *ifindex); */

	/* ignore attributes */
	return MNL_CB_STOP;
}

static int pe_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, OVS_BPF_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case OVS_BPF_ATTR_UNSPEC:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int pe_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	uint32_t *val = data;
	struct nlattr *tb[OVS_BPF_ATTR_UNSPEC+1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct ovs_header *ovs;

	ovs = mnl_nlmsg_get_payload_offset(nlh, sizeof(*genl));

	ret = mnl_attr_parse(nlh, sizeof(*genl) + sizeof(*ovs), pe_attr_cb, tb);
	if (ret <= MNL_CB_STOP) {
		return ret;
	}
	if (tb[OVS_BPF_ATTR_UNSPEC]) {
		*val = mnl_attr_get_u32(tb[OVS_BPF_ATTR_UNSPEC]);

		/* ignore the rest */
		return MNL_CB_STOP;
	}

	return MNL_CB_OK;
}

static int read_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, OVS_BPF_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case OVS_BPF_ATTR_UNSPEC:
		if (mnl_attr_validate(attr, MNL_TYPE_UNSPEC) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

struct read_data {
	uint8_t *data;
	uint32_t len;
};

static int read_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	struct read_data *read = data;
	struct nlattr *tb[OVS_BPF_ATTR_UNSPEC+1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct ovs_header *ovs;

	ovs = mnl_nlmsg_get_payload_offset(nlh, sizeof(*genl));

	ret = mnl_attr_parse(nlh, sizeof(*genl) + sizeof(*ovs), read_attr_cb,
			     tb);
	if (ret <= MNL_CB_STOP) {
		return ret;
	}
	if (tb[OVS_BPF_ATTR_UNSPEC]) {
		read->len = mnl_attr_get_payload_len(tb[OVS_BPF_ATTR_UNSPEC]);
		read->data = mnl_attr_get_payload(tb[OVS_BPF_ATTR_UNSPEC]);

		/* ignore the rest */
		return MNL_CB_STOP;
	}

	return MNL_CB_OK;
}

static int dump_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	struct read_data *read = data;
	struct nlattr *tb[OVS_BPF_ATTR_UNSPEC+1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct ovs_header *ovs;
	uint8_t *unspec;
	int unspec_len;

	ovs = mnl_nlmsg_get_payload_offset(nlh, sizeof(*genl));

	ret = mnl_attr_parse(nlh, sizeof(*genl) + sizeof(*ovs), read_attr_cb,
			     tb);
	if (ret <= MNL_CB_STOP) {
		return ret;
	}
	if (tb[OVS_BPF_ATTR_UNSPEC]) {
		unspec = mnl_attr_get_payload(tb[OVS_BPF_ATTR_UNSPEC]);
		unspec_len = mnl_attr_get_payload_len(tb[OVS_BPF_ATTR_UNSPEC]);
		if (read->len + unspec_len > MAX_DUMP_BUF_SIZE)
			return MNL_CB_STOP;
		memcpy(read->data, unspec, unspec_len);
		read->len += unspec_len;
		read->data += unspec_len;
	}

	return MNL_CB_OK;
}

static int create_dp(void)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	uint32_t val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= dp_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_DP_CMD_NEW;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = 0;

	mnl_attr_put_strz(nlh, OVS_DP_ATTR_NAME, "ovs-bpf");
	mnl_attr_put_u32(nlh, OVS_DP_ATTR_UPCALL_PID, 0);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}
	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, dp_new_cb, &dp_ifindex);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}
	return 0;
}

static int upcall_attr_cb(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	const struct nlattr **tb = data;
	static int packet_cnt;

	if (mnl_attr_type_valid(attr, __OVS_PACKET_ATTR_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case OVS_PACKET_ATTR_PACKET:
		if (mnl_attr_validate(attr, MNL_TYPE_UNSPEC) < 0) {
			return MNL_CB_ERROR;
		}
		/*printf("got packet #%d len %d\n", ++packet_cnt,
		       mnl_attr_get_payload_len(attr));*/
		break;
	case OVS_PACKET_ATTR_USERDATA:
		if (mnl_attr_validate(attr, MNL_TYPE_UNSPEC) < 0) {
			return MNL_CB_ERROR;
		}
		/*printf("got user data len %d\n",
		       mnl_attr_get_payload_len(attr));*/
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static channel_handler_t channel_handler;

void register_channel_handler(channel_handler_t handler)
{
	channel_handler = handler;
}

static int upcall_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	struct read_data *read = data;
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct ovs_header *ovs;
	struct nlattr *tb[OVS_PACKET_ATTR_MAX] = {};

	ovs = mnl_nlmsg_get_payload_offset(nlh, sizeof(*genl));

	ret = mnl_attr_parse(nlh, sizeof(*genl) + sizeof(*ovs), upcall_attr_cb,
			     tb);
	if (ret <= MNL_CB_STOP)
		return ret;
	if (tb[OVS_PACKET_ATTR_PACKET]) {
		read->len = mnl_attr_get_payload_len(tb[OVS_PACKET_ATTR_PACKET]);
		read->data = mnl_attr_get_payload(tb[OVS_PACKET_ATTR_PACKET]);
	}

	return MNL_CB_OK;
}

static void *upcall_thread(void *ctx)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct read_data read;
	int ret;

	ret = mnl_socket_recvfrom(ch_sock, buf, sizeof(buf));
	if (ret < 0) {
		printf("upcall error %s\n", strerror(errno));
		return 0;
	}

	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, ch_portid, upcall_cb, &read);
		if (ret < 0) {
			printf("upcall error %s\n", strerror(errno));
			return 0;
		}

		if (read.len && channel_handler)
			(*channel_handler)(read.data, read.len);

		if (ret <= MNL_CB_STOP)
			break;

		read.len = 0;
		ret = mnl_socket_recvfrom(ch_sock, buf, sizeof(buf));
	}
	return 0;
}

int init_iovisor(void)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	uint32_t val;
	unsigned int opt = 1;

        ret = genl_lookup_family(OVS_DATAPATH_FAMILY, &dp_family_id);
        if (ret)
		return ret;

        ret = genl_lookup_family(OVS_VPORT_FAMILY, &vport_family_id);
        if (ret)
		return ret;

        ret = genl_lookup_family(OVS_BPF_FAMILY, &pe_family_id);
        if (ret)
		return ret;

	/* see if DP is already created */
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= dp_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_DP_CMD_GET;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = 0;

	mnl_attr_put_strz(nlh, OVS_DP_ATTR_NAME, "ovs-bpf");

	/* open control socket */
	sock = mnl_socket_open(NETLINK_GENERIC);
	if (sock == NULL) {
		return -errno;
	}

	if (mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		return -errno;
	}

	portid = mnl_socket_get_portid(sock);

	/* open upcall socket */
	ch_sock = mnl_socket_open(NETLINK_GENERIC);
	if (ch_sock == NULL) {
		return -errno;
	}

	if (mnl_socket_setsockopt(ch_sock, NETLINK_NO_ENOBUFS, &opt,
				  sizeof(opt)) < 0) {
		return -errno;
	}

	if (mnl_socket_bind(ch_sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		return -errno;
	}

	ch_portid = mnl_socket_get_portid(ch_sock);
	pthread_create(&upcall_thread_id, NULL, upcall_thread, NULL);

	/* use control socket from now on */
	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	/* lookup miss error will be acked by genl */
	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;

	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, dp_new_cb, &dp_ifindex);
		if (ret < 0) {
			if (errno == ENODEV) {
				return create_dp();
			}
			return -errno;
		}
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	return 0;
}

int reset_iovisor(void)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	uint32_t val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= dp_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_DP_CMD_DEL;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, dp_new_cb, &dp_ifindex);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	return ret;
}

static int vport_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, OVS_VPORT_ATTR_PORT_NO) < 0)
		return MNL_CB_OK;

	switch(type) {
	case OVS_VPORT_ATTR_PORT_NO:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int vport_new_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret;
	int *port = data;
	struct nlattr *tb[OVS_VPORT_ATTR_PORT_NO+1] = {};
	struct genlmsghdr *genl = mnl_nlmsg_get_payload(nlh);
	struct ovs_header *ovs;

	ovs = mnl_nlmsg_get_payload_offset(nlh, sizeof(*genl));

	ret = mnl_attr_parse(nlh, sizeof(*genl) + sizeof(*ovs), vport_attr_cb, tb);
	if (ret <= MNL_CB_STOP) {
		return ret;
	}
	if (tb[OVS_VPORT_ATTR_PORT_NO]) {
		*port = mnl_attr_get_u32(tb[OVS_VPORT_ATTR_PORT_NO]);
		/* ignore the rest */
		return MNL_CB_STOP;
	}

	return MNL_CB_OK;
}

int lookup_port(const char *name, int *portno)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int fd;
	struct ifreq ifr;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= vport_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_VPORT_CMD_GET;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_strz(nlh, OVS_VPORT_ATTR_NAME, name);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, vport_new_cb, portno);
		if (ret < 0) {
			if (errno == ENODEV) {
				*portno = 0;
				return 0;
			}
			return -errno;
		}
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	return 0;
}

int add_port(const char *name, int *portno, int vport_type)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int fd;
	struct ifreq ifr;
	struct nlattr *nest;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= vport_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_VPORT_CMD_NEW;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_strz(nlh, OVS_VPORT_ATTR_NAME, name);
	mnl_attr_put_u32(nlh, OVS_VPORT_ATTR_TYPE, vport_type);
	mnl_attr_put_u32(nlh, OVS_VPORT_ATTR_UPCALL_PID, 0);
	if (vport_type == OVS_VPORT_TYPE_VXLAN) {
		nest = mnl_attr_nest_start(nlh, OVS_VPORT_ATTR_OPTIONS);
		mnl_attr_put_u16(nlh, OVS_TUNNEL_ATTR_DST_PORT, 0x5678);
		mnl_attr_nest_end(nlh, nest);
		nest->nla_type &= ~NLA_F_NESTED;
	}

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, vport_new_cb, portno);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (!*portno)
		return -1;

	return 0;
}

int register_plum(int *plum_id, struct bpf_insn insns[], uint32_t insns_sz,
		  unsigned int tables[], uint32_t tables_sz)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	uint32_t val = 0;
	struct bpf_image image;

	image.insns = (struct bpf_insn *)insns;
	image.insn_cnt = insns_sz / sizeof(struct bpf_insn) - 1;
	image.tables = (struct bpf_table *)tables;
	image.table_cnt = tables_sz ? (tables_sz / sizeof(struct bpf_table) - 1) : 0;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_REGISTER_PLUM;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put(nlh, OVS_BPF_ATTR_PLUM, sizeof(image), &image);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_UPCALL_PID, ch_portid);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, 0);

	ret = mnl_socket_sendto(sock, nlh, nlh->nlmsg_len);
	if (ret < 0)
		return ret;

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return ret;
	while (ret >= 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	*plum_id = val;

	return 0;
}

int connect_ports(int plum_id, int port_id, int dest_plum_id, int dest_port_id)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_CONNECT_PORTS;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PORT_ID, port_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_DEST_PLUM_ID, dest_plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_DEST_PORT_ID, dest_port_id);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

int disconnect_ports(int plum_id, int port_id, int dest_plum_id, int dest_port_id)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_DISCONNECT_PORTS;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PORT_ID, port_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_DEST_PLUM_ID, dest_plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_DEST_PORT_ID, dest_port_id);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

int add_replicator_port(int plum_id, int handle, int port_id)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_ADD_PORT_TO_REPLICATOR;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PORT_ID, port_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_REPLICATOR_ID, handle);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

int unregister_plum(int plum_id)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	uint32_t val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_UNREGISTER_PLUM;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != plum_id)
		return -1;

	return 0;
}

int del_port(int portno)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int ret_port;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= vport_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ECHO;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_VPORT_CMD_DEL;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_VPORT_ATTR_PORT_NO, portno);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, vport_new_cb, &ret_port);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (ret_port != portno)
		return -1;

	return 0;
}

int del_replicator_port(int plum_id, int handle, int port_id)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_DEL_PORT_FROM_REPLICATOR;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PORT_ID, port_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_REPLICATOR_ID, handle);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

int delete_replicator(int plum_id, int handle)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_DEL_REPLICATOR;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_REPLICATOR_ID, handle);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

int clear_elements(int plum_id, uint32_t table_id)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_CLEAR_TABLE_ELEMENTS;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_TABLE_ID, table_id);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

int update_element(int plum_id, uint32_t table_id, void *key,
		   int key_size, void *leaf, int leaf_size)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_UPDATE_TABLE_ELEMENT;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_TABLE_ID, table_id);
	mnl_attr_put(nlh, OVS_BPF_ATTR_KEY_OBJ, key_size, key);
	mnl_attr_put(nlh, OVS_BPF_ATTR_LEAF_OBJ, leaf_size, leaf);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

int delete_element(int plum_id, uint32_t table_id, void *key,
		   int key_size)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	int val;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_DELETE_TABLE_ELEMENT;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_TABLE_ID, table_id);
	mnl_attr_put(nlh, OVS_BPF_ATTR_KEY_OBJ, key_size, key);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

void *read_element(int plum_id, uint32_t table_id, void *key,
		   int key_size, int *leaf_size)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	struct read_data read;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_READ_TABLE_ELEMENT;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_TABLE_ID, table_id);
	mnl_attr_put(nlh, OVS_BPF_ATTR_KEY_OBJ, key_size, key);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return NULL;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, read_cb, &read);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (ret == MNL_CB_ERROR)
		return NULL;

	*leaf_size = read.len;

	return read.data;
}

int dump_element(int plum_id, uint32_t table_id, uint8_t *read_buf, int *read_len)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	struct read_data read;

	if (!read_buf)
		return -1;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_READ_TABLE_ELEMENT;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_TABLE_ID, table_id);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	read.data = read_buf;
	read.len = 0;

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, dump_cb, &read);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (ret == MNL_CB_ERROR)
		return -1;

	*read_len = read.len;

	return 0;
}

int channel_push(uint32_t plum_id, uint32_t port_id, uint8_t *packet,
		 uint32_t len)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	struct read_data read;
	uint32_t val = 0;

	if (!packet)
		return -1;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_CHANNEL_PUSH;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PORT_ID, port_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_FWD_PLUM_ID, 0);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_ARG1, 0);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_ARG2, 0);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_ARG3, 0);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_ARG4, 0);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_DIRECTION, OVS_BPF_IN_DIR);
	mnl_attr_put(nlh, OVS_BPF_ATTR_PACKET, len, packet);

	if (mnl_socket_sendto(sock, nlh, nlh->nlmsg_len) < 0) {
		return -errno;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	if (ret < 0)
		return -errno;
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, pe_cb, &val);
		if (ret < 0)
			return -errno;
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (val != 0)
		return -1;

	return 0;
}

int read_port_stats(int plum_id, uint32_t port_id,
		    struct ovs_bpf_port_stats *stats)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header *ovs;
	struct read_data read;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= pe_family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 0;

	genl = mnl_nlmsg_put_extra_header(nlh, sizeof(struct genlmsghdr));
	genl->cmd = OVS_BPF_CMD_READ_PORT_STATS;
	genl->version = 1;

	ovs = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ovs_header));
	ovs->dp_ifindex = dp_ifindex;

	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PLUM_ID, plum_id);
	mnl_attr_put_u32(nlh, OVS_BPF_ATTR_PORT_ID, port_id);

	ret = mnl_socket_sendto(sock, nlh, nlh->nlmsg_len);
	if (ret < 0) {
		return ret;
	}

	ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, 0, portid, read_cb, &read);
		if (ret <= MNL_CB_STOP)
			break;
		ret = mnl_socket_recvfrom(sock, buf, sizeof(buf));
	}

	if (ret == MNL_CB_ERROR)
		return -1;

	if (read.len != sizeof(struct ovs_bpf_port_stats)) {
		printf("invalid read_port_stats size %d\n", read.len);
		return -EINVAL;
	}

	memcpy(stats, read.data, sizeof(struct ovs_bpf_port_stats));

	return 0;
}
