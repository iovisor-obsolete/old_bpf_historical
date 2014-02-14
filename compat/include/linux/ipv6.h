#ifndef __LINUX_IPV6_WRAPPER_H
#define __LINUX_IPV6_WRAPPER_H 1

#include_next <linux/ipv6.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0) && \
	(!defined(RHEL_RELEASE_CODE) || \
	(RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6, 5)))
enum {
        IP6_FH_F_FRAG           = (1 << 0),
        IP6_FH_F_AUTH           = (1 << 1),
        IP6_FH_F_SKIP_RH        = (1 << 2),
};
#endif

#ifndef HAVE_SKBUFF_HEADER_HELPERS
static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_network_header(skb);
}
#endif

#endif
