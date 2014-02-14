#ifndef __LINUX_RCULIST_WRAPPER_H
#define __LINUX_RCULIST_WRAPPER_H

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include_next <linux/rculist.h>
#else
/* Prior to 2.6.26, the contents of rculist.h were part of list.h. */
#include <linux/list.h>
#include <linux/rcupdate.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#define hlist_del_init_rcu rpl_hlist_del_init_rcu
static inline void hlist_del_init_rcu(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		n->pprev = NULL;
	}
}
#endif

#ifndef hlist_first_rcu
#define hlist_first_rcu(head)   (*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)    (*((struct hlist_node __rcu **)(&(node)->next)))
#define hlist_pprev_rcu(node)   (*((struct hlist_node __rcu **)((node)->pprev)))
#endif

#undef hlist_for_each_entry_rcu
#define hlist_for_each_entry_rcu(pos, head, member)			\
	for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))

#if LINUX_VERSION_CODE < KERNEL_VERSION(1,10,0)
static inline void hlist_add_head_rcu(struct hlist_node *n,
					struct hlist_head *h)
{
	struct hlist_node *first = h->first;

	n->next = first;
	n->pprev = &h->first;
	rcu_assign_pointer(hlist_first_rcu(h), n);
	if (first)
		first->pprev = &n->next;
}
#endif
#endif
