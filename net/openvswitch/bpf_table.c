/* Copyright (c) 2011-2013 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */
#include <linux/rculist.h>
#include <linux/filter.h>
#include <linux/jhash.h>
#include "datapath.h"

static inline void *table_priv(const struct plum_table *table)
{
	return (u8 *)table + ALIGN(sizeof(struct plum_table), PLUM_TABLE_ALIGN);
}

#define HASH_TABLE(tb) ((struct plum_hash_table *)table_priv(tb))
#define LPM_TABLE(tb) ((struct plum_lpm_table *)table_priv(tb))

static inline void *elem_priv(const struct plum_elem *elem)
{
	return (u8 *)elem + ALIGN(sizeof(struct plum_elem), PLUM_ELEM_ALIGN);
}

static inline struct plum_elem *elem_from_priv(const void *priv)
{
	return (struct plum_elem *)(priv - ALIGN(sizeof(struct plum_elem),
						 PLUM_ELEM_ALIGN));
}

#define HASH_ELEM(l) ((struct plum_hash_elem *)elem_priv(l))
#define LPM_ELEM(l) ((struct plum_lpm_elem *)elem_priv(l))

static void *alloc_table_elem(struct plum_table *table)
{
	void *l;

	l = kmem_cache_alloc(table->leaf_cache, GFP_ATOMIC);
	if (!l)
		return ERR_PTR(-ENOMEM);
        return l;
}

static void free_table_elem_rcu(struct rcu_head *rcu)
{
	struct plum_elem *l = container_of(rcu, struct plum_elem, rcu);

	kmem_cache_free(l->table->leaf_cache, l);
}

static void release_table_elem(struct plum_table *table, void *l_priv)
{
	struct plum_elem *l = elem_from_priv(l_priv);

	l->table = table;
	call_rcu(&l->rcu, free_table_elem_rcu);
}

static void free_table(struct plum_table *table)
{
	if (!table)
		return;

	if (!table->leaf_cache)
		goto free_table;

	if (table->info.type == BPF_TABLE_HASH)
		kfree(HASH_TABLE(table)->buckets);
	else if (table->info.type == BPF_TABLE_LPM)
		kfree(LPM_TABLE(table)->root);

	kmem_cache_destroy(table->leaf_cache);
	kfree(table->slab_name);
free_table:
	kfree(table);
}

static inline u32 hash_table_hash(const void *key, u32 key_len)
{
	return jhash(key, key_len, 0);
}

static inline
struct hlist_head *hash_table_find_bucket(struct plum_table *table,
					  u32 hash)
{
	struct plum_hash_table *htable = HASH_TABLE(table);
	return &htable->buckets[hash & (htable->n_buckets - 1)];
}

/* Must be called with rcu_read_lock. */
static struct plum_hash_elem *hash_table_lookup(struct plum_table *table,
						const void *key, u32 key_len,
						u32 hit_cnt)
{
	struct plum_hash_elem *l;
	struct hlist_head *head;
	u32 hash;

	WARN_ON_ONCE(!rcu_read_lock_held());

	if (!key)
		return NULL;

	hash = hash_table_hash(key, key_len);

	head = hash_table_find_bucket(table, hash);
	hlist_for_each_entry_rcu(l, head, hash_node) {
		if (l->hash == hash && !memcmp(&l->key, key, key_len)) {
			if (hit_cnt)
				atomic_inc(&l->hit_cnt);
			return l;
		}
	}
	return NULL;
}

static void hash_table_clear_elements(struct plum_table *table)
{
	struct plum_hash_table *htable = HASH_TABLE(table);
	int i;

	spin_lock_bh(&table->lock);
	for (i = 0; i < htable->n_buckets; i++) {
		struct plum_hash_elem *l;
		struct hlist_head *head = hash_table_find_bucket(table, i);
		struct hlist_node *n;

		hlist_for_each_entry_safe(l, n, head, hash_node) {
			hlist_del_rcu(&l->hash_node);
			table->count--;
			release_table_elem(table, l);
		}
	}
	spin_unlock_bh(&table->lock);
	WARN_ON(table->count != 0);
}

static struct plum_hash_elem *hash_table_find(struct plum_table *table,
					      const void *key, u32 key_len)
{
	return hash_table_lookup(table, key, key_len, 0);
}

static void hash_table_remove(struct plum_table *table,
			      struct plum_hash_elem *l)
{
	if (!l)
		return;

	spin_lock_bh(&table->lock);
	hlist_del_rcu(&l->hash_node);
	table->count--;
	release_table_elem(table, l);
	spin_unlock_bh(&table->lock);
	WARN_ON(table->count < 0);
}

static int hash_table_update_element(struct plum_table *table,
				     const char *key_data, u32 key_size,
				     const char *leaf_data, u32 leaf_size)
{
	struct plum_elem *l;
	struct plum_hash_elem *l_new;
	struct plum_hash_elem *l_old;
	struct hlist_head *head;

	l = alloc_table_elem(table);
	if (IS_ERR(l))
		return -ENOMEM;
	l_new = HASH_ELEM(l);
	atomic_set(&l_new->hit_cnt, 0);
	memcpy(&l_new->key, key_data, key_size);
	memcpy(&l_new->key[key_size], leaf_data, leaf_size);
	l_new->hash = hash_table_hash(&l_new->key, key_size);
	head = hash_table_find_bucket(table, l_new->hash);

	rcu_read_lock();
	l_old = hash_table_find(table, key_data, key_size);

	spin_lock_bh(&table->lock);
	if (!l_old && table->count >= table->max_entries) {
		kmem_cache_free(table->leaf_cache, l);
		spin_unlock_bh(&table->lock);
		rcu_read_unlock();
		return -EFBIG;
	}
	hlist_add_head_rcu(&l_new->hash_node, head);
	if (l_old) {
		hlist_del_rcu(&l_old->hash_node);
		release_table_elem(table, l_old);
	} else {
		table->count++;
	}
	spin_unlock_bh(&table->lock);

	rcu_read_unlock();

	return 0;
}

/* Must be called with rcu_read_lock. */
static void *hash_table_read_element_next(struct plum_table *table,
					  long *row, long *last)
{
	struct plum_hash_table *htable = HASH_TABLE(table);
	struct plum_hash_elem *l;
	struct hlist_head *head;
	int i;

	while (*row < htable->n_buckets) {
		i = 0;
		head = &htable->buckets[*row];
		hlist_for_each_entry_rcu(l, head, hash_node) {
			if (i < *last) {
				i++;
				continue;
			}
			*last = i + 1;
			return (void *)&l->hit_cnt.counter;
		}
		(*row)++;
		*last = 0;
	}

	return NULL;
}

#define HASH_MAX_BUCKETS 1024
static int hash_table_init(struct plum_table *table)
{
	struct plum_hash_table *htable = HASH_TABLE(table);
	int ret;
	int i;
	u32 n_buckets = (table->info.max_entries <= HASH_MAX_BUCKETS) ?
			table->info.max_entries : HASH_MAX_BUCKETS;

	/* hash table size must be power of 2 */
	if ((n_buckets & (n_buckets - 1)) != 0) {
		pr_err("pg_hash_table_init size %d is not power of 2\n",
		       n_buckets);
		return -EINVAL;
	}

	htable->n_buckets = n_buckets;

	ret = -ENOMEM;
	htable->buckets = kmalloc(n_buckets * sizeof(struct hlist_head),
				  GFP_KERNEL);
	if (!htable->buckets)
		goto err;

	for (i = 0; i < n_buckets; i++)
		INIT_HLIST_HEAD(&htable->buckets[i]);

	/* leaf_cache is allocated last */
	table->leaf_size += sizeof(struct plum_hash_elem);
	table->slab_name = kasprintf(GFP_KERNEL, "plum_hashtbl_%p", table);
	if (!table->slab_name)
		goto err_free_buckets;

	table->leaf_cache = kmem_cache_create(table->slab_name,
					      table->leaf_size, 0, 0, NULL);
	if (!table->leaf_cache)
		goto err_free_slab_name;

	return 0;

err_free_slab_name:
	kfree(table->slab_name);
err_free_buckets:
	kfree(htable->buckets);
err:
	return ret;
}

/* radix tree index is unsigned long in host order
 * assume caller checks that key_size <= sizeof(unsigned long) and
 * key is in host order
 */
static inline unsigned long lpm_key_to_radix_index(const char *key_data, u32 key_size)
{
	unsigned long index = 0;

	/* zero extend the key to unsigned long */
#ifdef __LITTLE_ENDIAN
	memcpy(&index, key_data, key_size);
#else
	char *ptr = (char *)&index + sizeof(unsigned long) - key_size;
	memcpy(ptr, key_data, key_size);
#endif

	return index;
}

static inline int lpm_nbits_to_radix_plen(u32 key_size, u32 n_bits)
{
	int plen;

	/* zero extend the key to unsigned long */
	plen = n_bits + BITS_PER_LONG - 8 * key_size;

	return plen;
}

/* Must be called with rcu_read_lock. */
static struct plum_lpm_elem *lpm_table_lookup(struct plum_table *table,
					      const void *key, u32 key_len,
					      u32 hit_cnt)
{
	struct plum_lpm_table *ltable = LPM_TABLE(table);
	unsigned long index;
	struct plum_lpm_elem *l;

	WARN_ON_ONCE(!rcu_read_lock_held());

	if (!key || key_len > sizeof(unsigned long))
		return NULL;

	index = lpm_key_to_radix_index(key, key_len);

	l = radix_tree_lookup_lpm(ltable->root, index);
	if (l && hit_cnt)
		atomic_inc(&l->hit_cnt);

	return l;
}

#define LPM_GANG_SIZE 16
static void lpm_table_clear_elements(struct plum_table *table)
{
	struct plum_lpm_table *ltable = LPM_TABLE(table);
	struct hlist_node *nodes[LPM_GANG_SIZE];
	struct hlist_head *head;
	struct radix_tree_lpm_info *li;
	struct hlist_node *n;
	unsigned long index = 0;
	int count;
	int i;
	struct plum_lpm_elem *l;

	spin_lock_bh(&table->lock);

	do {
		count = radix_tree_gang_lookup(ltable->root, (void **)nodes,
					       index, LPM_GANG_SIZE);

		for (i = 0; i < count; i++) {
			/* nodes[i] is the first hlist_node for that slot */
			head = (struct hlist_head *)nodes[i]->pprev;
			if (!head) {
				/* special case after index 0 is moved from
				 * rnode to node[0]
				 */
				l = (struct plum_lpm_elem *)nodes[i];
				index = lpm_key_to_radix_index(l->key + sizeof(u32),
							       table->key_size);
				l = radix_tree_delete_lpm(ltable->root, index,
							  l->info.plen);
				if (l) {
					release_table_elem(table, l);
					table->count--;
				}
				continue;
			}
			hlist_for_each_entry_safe(li, n, head, hlist) {
				l = container_of(li, struct plum_lpm_elem,
						 info);
				index = lpm_key_to_radix_index(l->key + sizeof(u32),
							       table->key_size);
				l = radix_tree_delete_lpm(ltable->root, index,
							  l->info.plen);
				if (l) {
					release_table_elem(table, l);
					table->count--;
				}
			}
		}

		index++;
	} while (count == LPM_GANG_SIZE);

	spin_unlock_bh(&table->lock);
	WARN_ON(table->count != 0);
	WARN_ON(ltable->root->rnode != NULL);
}

static struct plum_lpm_elem *lpm_table_find(struct plum_table *table,
					    const void *key, u32 key_len,
					    u32 n_bits)
{
	struct plum_lpm_table *ltable = LPM_TABLE(table);
	unsigned long index;
	int plen;

	index = lpm_key_to_radix_index(key, key_len);
	plen = lpm_nbits_to_radix_plen(key_len, n_bits);

	return radix_tree_find_lpm(ltable->root, index, plen);
}

static int lpm_table_update_element(struct plum_table *table,
				    const char *key_data, u32 key_size,
				    const char *leaf_data, u32 leaf_size)
{
	struct plum_lpm_table *ltable = LPM_TABLE(table);
	u32 n_bits;
	struct plum_elem *l;
	struct plum_lpm_elem *l_new;
	struct plum_lpm_elem *l_old;
	struct radix_tree_lpm_info *info;
	unsigned long index;
	int ret;

	if (key_size > sizeof(unsigned long))
		return -EINVAL;

	n_bits = *(u32 *)key_data;
	l = alloc_table_elem(table);
	if (IS_ERR(l))
		return -ENOMEM;
	l_new = LPM_ELEM(l);
	atomic_set(&l_new->hit_cnt, 0);
	memcpy(&l_new->key, key_data, key_size + sizeof(n_bits));
	memcpy(&l_new->key[key_size + sizeof(n_bits)], leaf_data, leaf_size);

	info = &l_new->info;
	INIT_HLIST_NODE(&info->hlist);
	info->plen = lpm_nbits_to_radix_plen(key_size, n_bits);
	key_data += sizeof(n_bits);
	index = lpm_key_to_radix_index(key_data, key_size);

	spin_lock_bh(&table->lock);
	l_old = radix_tree_delete_lpm(ltable->root, index, info->plen);
	if (!l_old && table->count >= table->max_entries) {
		kmem_cache_free(table->leaf_cache, l_new);
		spin_unlock_bh(&table->lock);
		return -EFBIG;
	}

	if (l_old) {
		release_table_elem(table, l_old);
		table->count--;
	}

	ret = radix_tree_insert_lpm(ltable->root, index, l_new);
	if (!ret)
		table->count++;

	spin_unlock_bh(&table->lock);

	return ret;
}

/* Must be called with rcu_read_lock. */
static void *lpm_table_read_element_next(struct plum_table *table,
					 long *row, long *last)
{
	struct plum_lpm_table *ltable = LPM_TABLE(table);
	struct plum_lpm_elem *l;
	struct hlist_node *nodes[2];
	struct hlist_head *head;
	struct radix_tree_lpm_info *li;
	int count;
	int i, j;

	count = radix_tree_gang_lookup(ltable->root, (void **)nodes, *row, 2);
	for (i = 0; i < count; i++) {
		j = 0;
		/* nodes[i] is the first hlist_node for that slot */
		head = (struct hlist_head *)nodes[i]->pprev;
		if (!head) {
			/* special case after index 0 is moved from rnode to
			 * node[0]
			 */
			*last = 0;
			l = (struct plum_lpm_elem *)nodes[i];
			*row = lpm_key_to_radix_index(l->key + sizeof(u32),
						      table->key_size) + 1;
			return (void *)&l->hit_cnt.counter;
		}
		hlist_for_each_entry_rcu(li, head, hlist) {
			if (j < *last) {
				j++;
				continue;
			}
			*last = j + 1;
			l = container_of(li, struct plum_lpm_elem, info);
			*row = lpm_key_to_radix_index(l->key + sizeof(u32),
						      table->key_size);
			return (void *)&l->hit_cnt.counter;
		}
		*last = 0;
	}

	return NULL;
}

static int lpm_table_init(struct plum_table *table)
{
	struct plum_lpm_table *ltable = LPM_TABLE(table);
	int ret;

	ret = -ENOMEM;

	ltable->root = kzalloc(sizeof(struct radix_tree_root), GFP_KERNEL);
	if (!ltable->root)
		goto err;

	INIT_RADIX_TREE(ltable->root, GFP_ATOMIC);

	/* leaf_cache is allocated last */
	table->leaf_size += sizeof(struct plum_lpm_elem);
	table->slab_name = kasprintf(GFP_KERNEL, "plum_lpmtbl_%p", table);
	if (!table->slab_name)
		goto err_free_root;

	table->leaf_cache = kmem_cache_create(table->slab_name,
					      table->leaf_size, 0, 0, NULL);
	if (!table->leaf_cache)
		goto err_free_slab_name;

	return 0;

err_free_slab_name:
	kfree(table->slab_name);
err_free_root:
	kfree(ltable->root);
err:
	return ret;
}

static struct plum_table *get_table(struct plum *plum, u32 table_id)
{
	int i;
	struct plum_table *table;

	for (i = 0; i < plum->num_tables; i++) {
		table = plum->tables[i];

		if (table->info.id == table_id)
			return table;
	}

	return NULL;
}

int bpf_dp_clear_table_elements(struct plum *plum, u32 table_id)
{
	struct plum_table *table;

	table = get_table(plum, table_id);
	if (!table)
		return -EINVAL;

	if (table->info.type == BPF_TABLE_HASH)
		hash_table_clear_elements(table);
	else if (table->info.type == BPF_TABLE_LPM)
		lpm_table_clear_elements(table);

	return 0;
}

int bpf_dp_update_table_element(struct plum *plum, u32 table_id,
				const char *key_data, const char *leaf_data)
{
	struct plum_table *table;
	u32 key_size, leaf_size;
	int ret = 0;

	table = get_table(plum, table_id);
	if (!table)
		return -EINVAL;

	key_size = table->info.key_size;
	leaf_size = table->info.elem_size;

	if (table->info.type == BPF_TABLE_HASH)
		ret = hash_table_update_element(table, key_data, key_size,
						leaf_data, leaf_size);
	else if (table->info.type == BPF_TABLE_LPM)
		ret = lpm_table_update_element(table, key_data, key_size,
					       leaf_data, leaf_size);

	return ret;
}

int bpf_dp_delete_table_element(struct plum *plum, u32 table_id,
				const char *key_data)
{
	struct plum_table *table;
	u32 key_size;

	table = get_table(plum, table_id);
	if (!table)
		return -EINVAL;

	key_size = table->info.key_size;

	if (table->info.type == BPF_TABLE_HASH) {
		struct plum_hash_elem *l;
		rcu_read_lock();
		l = hash_table_find(table, key_data, key_size);
		if (l)
			hash_table_remove(table, l);
		rcu_read_unlock();
	} else if (table->info.type == BPF_TABLE_LPM) {
		struct plum_lpm_elem *l;
		u32 n_bits;
		unsigned long index;
		int plen;

		n_bits = *(u32 *)key_data;
		key_data += sizeof(n_bits);
		index = lpm_key_to_radix_index(key_data, key_size);
		plen = lpm_nbits_to_radix_plen(key_size, n_bits);
		spin_lock_bh(&table->lock);
		l = radix_tree_delete_lpm(LPM_TABLE(table)->root, index, plen);
		if (l) {
			release_table_elem(table, l);
			table->count--;
		}
		spin_unlock_bh(&table->lock);
	}

	return 0;
}

/* Must be called with rcu_read_lock. */
void *bpf_dp_read_table_element(struct plum *plum, u32 table_id,
				const char *key_data, u32 *elem_size)
{
	struct plum_table *table;
	u32 key_size;

	table = get_table(plum, table_id);
	if (!table)
		return ERR_PTR(-EINVAL);

	key_size = table->info.key_size;
	*elem_size = key_size + table->info.elem_size + sizeof(int);

	if (table->info.type == BPF_TABLE_HASH) {
		struct plum_hash_elem *l;

		l = hash_table_find(table, key_data, key_size);
		if (l)
			return (void *)&l->hit_cnt.counter;
	} else if (table->info.type == BPF_TABLE_LPM) {
		struct plum_lpm_elem *l;
		u32 n_bits;

		*elem_size += sizeof(n_bits);
		n_bits = *(u32 *)key_data;
		key_data += sizeof(n_bits);

		l = lpm_table_find(table, key_data, key_size, n_bits);
		if (l)
			return (void *)&l->hit_cnt.counter;
	}

	return ERR_PTR(-ESRCH);
}

/* Must be called with rcu_read_lock. */
void *bpf_dp_read_table_element_next(struct plum *plum, u32 table_id,
				     long *row, long *last, u32 *elem_size)
{
	struct plum_table *table;
	u32 key_size;

	table = get_table(plum, table_id);
	if (!table)
		return ERR_PTR(-EINVAL);

	key_size = table->info.key_size;
	*elem_size = key_size + table->info.elem_size + sizeof(int);

	if (table->info.type == BPF_TABLE_HASH) {
		return hash_table_read_element_next(table, row, last);
	} else if (table->info.type == BPF_TABLE_LPM) {
		*elem_size += sizeof(u32);
		return lpm_table_read_element_next(table, row, last);
	}

	return NULL;
}

int init_plum_tables(struct plum *plum)
{
	int ret;
	int i;
	struct plum_table *table;

	for (i = 0; i < plum->num_tables; i++) {
		table = plum->tables[i];
		if (table->info.id > PLUM_MAX_TABLES) {
			pr_err("table_id %d is too large\n", table->info.id);
			continue;
		}

		spin_lock_init(&table->lock);
		table->max_entries = table->info.max_entries;
		table->key_size = table->info.key_size;
		table->leaf_size = sizeof(struct plum_elem);
		table->leaf_size += ALIGN(sizeof(struct plum_elem),
					  PLUM_ELEM_ALIGN);
		table->leaf_size += table->info.key_size +
				    table->info.elem_size;

		if (table->info.type == BPF_TABLE_HASH) {
			ret = hash_table_init(table);
			if (ret)
				goto err_cleanup;
		} else if (table->info.type == BPF_TABLE_LPM) {
			ret = lpm_table_init(table);
			if (ret)
				goto err_cleanup;
		} else {
			pr_err("table_type %d is unknown\n", table->info.type);
			ret = -EINVAL;
			goto err_cleanup;
		}
	}

	return 0;

err_cleanup:
	for (i = 0; i < plum->num_tables; i++) {
		free_table(plum->tables[i]);
		plum->tables[i] = NULL;
	}

	return ret;
}

void cleanup_plum_tables(struct plum *plum)
{
	int i;
	struct plum_table *table;

	for (i = 0; i < plum->num_tables; i++) {
		table = plum->tables[i];

		if (table->info.type == BPF_TABLE_HASH)
			hash_table_clear_elements(table);
		if (table->info.type == BPF_TABLE_LPM)
			lpm_table_clear_elements(table);
	}
}

void free_plum_tables(struct plum *plum)
{
	int i;

	for (i = 0; i < plum->num_tables; i++) {
		free_table(plum->tables[i]);
		plum->tables[i] = NULL;
	}

	kfree(plum->tables);
}

/* bpf_check() verified that 'pctx' is a valid pointer, table_id is a valid
 * table_id and 'key' points to valid region inside BPF program stack
 */
void *bpf_table_lookup(struct bpf_context *pctx, int table_id, const void *key)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct datapath *dp = ctx->dp;
	struct plum *plum;
	struct plum_table *table;

	if (!ctx->skb ||
	    ctx->context.plum_id >= DP_MAX_PLUMS)
		return NULL;

	plum = rcu_dereference(dp->plums[pctx->plum_id]);

	table = get_table(plum, table_id);
	if (!table) {
		pr_err("table_lookup plumg_id:table_id %d:%d not found\n",
		       ctx->context.plum_id, table_id);
		return NULL;
	}

	if (table->info.type == BPF_TABLE_HASH) {
		struct plum_hash_elem *helem;
		helem = hash_table_lookup(table, key, table->key_size, 1);
		if (helem)
			return helem->key + table->key_size;
	} else if (table->info.type == BPF_TABLE_LPM) {
		struct plum_lpm_elem *lelem;
		lelem = lpm_table_lookup(table, key, table->key_size, 1);
		if (lelem)
			return lelem->key + sizeof(u32) + table->key_size;
	}

	return NULL;
}

int bpf_table_update(struct bpf_context *pctx, int table_id, const void *key,
		     const void *leaf)
{
	struct bpf_dp_context *ctx = container_of(pctx, struct bpf_dp_context,
						  context);
	struct datapath *dp = ctx->dp;
	struct plum *plum;
	int ret;

	if (!ctx->skb ||
	    ctx->context.plum_id >= DP_MAX_PLUMS)
		return -EINVAL;

	plum = rcu_dereference(dp->plums[pctx->plum_id]);
	ret = bpf_dp_update_table_element(plum, table_id, key, leaf);

	return ret;
}
