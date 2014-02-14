#ifndef __NET_CHECKSUM_WRAPPER_H
#define __NET_CHECKSUM_WRAPPER_H 1

#include_next <net/checksum.h>

/* Workaround for debugging included in certain versions of XenServer.  It only
 * applies to 32-bit x86.
 */
#if defined(HAVE_CSUM_COPY_DBG) && defined(CONFIG_X86_32)
#define csum_and_copy_to_user(src, dst, len, sum, err_ptr) \
	csum_and_copy_to_user(src, dst, len, sum, NULL, err_ptr)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define inet_proto_csum_replace2(sum, skb, from, to, pseudohdr) \
	inet_proto_csum_replace4(sum, skb, (__force __be32)(from), \
					   (__force __be32)(to), pseudohdr)
#endif

#ifndef CSUM_MANGLED_0
#define CSUM_MANGLED_0 ((__force __sum16)0xffff)
#endif

extern void inet_proto_csum_replace16(__sum16 *sum, struct sk_buff *skb,
                                      const __be32 *from, const __be32 *to,
                                      int pseudohdr);
#endif /* checksum.h */
