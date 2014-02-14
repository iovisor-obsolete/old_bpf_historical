#ifndef _IF_TUNNEL_WRAPPER_H_
#define _IF_TUNNEL_WRAPPER_H_

#include <linux/version.h>
#include_next <linux/if_tunnel.h>

#include <linux/u64_stats_sync.h>

struct __pcpu_sw_netstats {
	u64     rx_packets;
	u64     rx_bytes;
	u64     tx_packets;
	u64     tx_bytes;
	struct u64_stats_sync   syncp;
};

#endif /* _IF_TUNNEL_WRAPPER_H_ */
