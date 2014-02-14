#ifndef __NET_SOCK_WRAPPER_H
#define __NET_SOCK_WRAPPER_H 1

#include_next <net/sock.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
struct net;

static inline struct net *sock_net(const struct sock *sk)
{
	return NULL;
}

#endif
#ifndef __sk_user_data
#define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))

#define rcu_dereference_sk_user_data(sk)       rcu_dereference(__sk_user_data((sk)))
#define rcu_assign_sk_user_data(sk, ptr)       rcu_assign_pointer(__sk_user_data((sk)), ptr)
#endif

#endif /* net/sock.h wrapper */
