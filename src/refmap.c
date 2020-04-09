// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/semaphore.h>

#include <mpcore/assert.h>
#include <mpcore/merr.h>
#include <mpcore/evc.h>

#include "refmap.h"

#ifndef SLAB_ACCOUNT
#define SLAB_ACCOUNT 0
#endif

#ifndef SLAB_POISON
#define SLAB_POISON 0
#endif

static inline uint
refmap_key_to_bktidx(u64 key)
{
	return key % REFMAP_BKT_MAX;
}

static inline u64
refmap_bktidx_to_key(uint bktidx)
{
	return bktidx;
}

merr_t
refmap_session_create(
	const char *name,
	size_t      size,
	struct refmap_session **sessionp)
{
	ulong flags = SLAB_ACCOUNT | SLAB_POISON;
	struct refmap_session *s;

	*sessionp = NULL;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (ev(!s))
		return merr(ENOMEM);

	size += sizeof(struct refmap_node);

	s->rs_cache = kmem_cache_create(name, size, 0, flags, NULL);
	if (ev(!s->rs_cache)) {
		kfree(s);
		return merr(ENOMEM);
	}

	atomic_set(&s->rs_refcnt, 1);
	s->rs_name = name;
	s->rs_size = size;

	*sessionp = s;

	return 0;
}


static void
refmap_session_get(struct refmap_session *session)
{
	atomic_inc(&session->rs_refcnt);
}

void
refmap_session_put(struct refmap_session *session)
{
	if (atomic_dec_return(&session->rs_refcnt) > 0)
		return;

	kmem_cache_destroy(session->rs_cache);
	kfree(session);
}

merr_t
refmap_create(
	struct refmap_session  *session,
	refmap_dtor_t          *dtor,
	void                   *dtor_arg,
	struct refmap         **refmapp)
{
	struct refmap  *refmap;
	int             i;

	refmap = kzalloc(sizeof(*refmap), GFP_KERNEL);
	if (ev(!refmap))
		return merr(ENOMEM);

	for (i = 0; i < REFMAP_BKT_MAX; ++i)
		init_rwsem(&refmap->rm_bktv[i].rb_lock);

	refmap->rm_dtor     = dtor ? dtor : refmap_node_free;
	refmap->rm_dtor_arg = dtor_arg;
	atomic_set(&refmap->rm_refcnt, 1);
	refmap->rm_session = session;

	refmap_session_get(session);

	*refmapp = refmap;

	return 0;
}

static void
refmap_get(struct refmap *refmap)
{
	atomic_inc(&refmap->rm_refcnt);
}

void
refmap_put(struct refmap *refmap)
{
	if (atomic_dec_return(&refmap->rm_refcnt) > 0)
		return;

	refmap_session_put(refmap->rm_session);
	kfree(refmap);
}

void
refmap_drop(struct refmap *refmap, int *nodes, int *refs)
{
	struct refmap_node *this;
	struct rb_node     *head;

	int     node_ct, ref_ct, i;

	if (ev(!refmap))
		return;

	head    = NULL;
	node_ct = 0;
	ref_ct  = 0;

	refmap_get(refmap);

	/* For each bucket in the map, move all idle nodes to the local
	 * linked list. Every idle node is considered leaked. If the app/DM
	 * had balanced gets/puts, there would be nothing in the refmap at
	 * close.
	 */
	for (i = 0; i < REFMAP_BKT_MAX; ++i) {
		struct refmap_bkt  *bkt;
		struct rb_node     *node;

		refmap_wlock(refmap, refmap_bktidx_to_key(i), &bkt);
		node = rb_first(&bkt->rb_root);
		if (!node) {
			refmap_wunlock(bkt);
			continue;
		}

		while (node) {
			this = rb_entry(node, struct refmap_node, rn_entry);
			node = rb_next(node);

			/* Every node we find was not put before dropping the
			 * refmap
			 */
			node_ct++;
			ref_ct += atomic_read(&this->rn_refcnt);

			rb_erase(&this->rn_entry, &bkt->rb_root);
			RB_CLEAR_NODE(&this->rn_entry);

			this->rn_entry.rb_right = head;
			head = &this->rn_entry;
		}

		/* If the bucket became empty, remove bucket ref from refmap */
		if (!bkt->rb_root.rb_node)
			refmap_put(refmap);
		++bkt->rb_gen;

		refmap_wunlock(bkt);
	}

	/* Destroy each refmap node on the linked list.
	 */
	while (head) {
		this = rb_entry(head, struct refmap_node, rn_entry);
		head = head->rb_right;

		/* The refmap_node is out of the refmap already; we just
		 * need to destruct it.
		 */
		if (refmap->rm_dtor)
			refmap->rm_dtor(this, refmap->rm_dtor_arg);
	}

	if (nodes)
		*nodes = node_ct;

	if (refs)
		*refs = ref_ct;

	refmap_put(refmap);
}

void
refmap_rlock(
	struct refmap      *refmap,
	u64                 key,
	u64                *genp,
	struct refmap_bkt **bktp)
{
	struct refmap_bkt  *bkt;
	uint                idx;

	idx = refmap_key_to_bktidx(key);
	bkt = refmap->rm_bktv + idx;

	down_read(&bkt->rb_lock);

	if (genp)
		*genp = bkt->rb_gen;

	*bktp = bkt;
}

void
refmap_runlock(struct refmap_bkt *bkt)
{
	up_read(&bkt->rb_lock);
}

void
refmap_wlock(struct refmap *refmap, u64 key, struct refmap_bkt **bktp)
{
	struct refmap_bkt  *bkt;
	uint                idx;

	idx = refmap_key_to_bktidx(key);
	bkt = refmap->rm_bktv + idx;

	down_write(&bkt->rb_lock);

	*bktp = bkt;
}

void
refmap_wunlock(struct refmap_bkt *bkt)
{
	up_write(&bkt->rb_lock);
}

static void
refmap_node_init(
	struct refmap      *refmap,
	u64                 key,
	void               *value,
	u64                 priv1,
	struct refmap_node *elem)
{
	elem->rn_key = key;
	RB_CLEAR_NODE(&elem->rn_entry);
	elem->rn_refmap = refmap;
	elem->rn_flags = 0;
	atomic_set(&elem->rn_refcnt, 1); /* birth reference */

	elem->rn_obj.ro_priv1 = priv1;
	elem->rn_obj.ro_value = value;
}

struct refmap_node *
refmap_node_alloc(
	struct refmap  *refmap,
	u64             key,
	void           *value,
	u64             priv1)
{
	struct refmap_node *elem;

	elem = kmem_cache_alloc(refmap->rm_session->rs_cache, GFP_KERNEL);
	if (elem)
		refmap_node_init(refmap, key, value, priv1, elem);

	return elem;
}

void
refmap_node_free(struct refmap_node *elem, void *arg)
{
	assert(elem);
	assert(elem->rn_refmap);
	assert(elem->rn_refmap->rm_session);
	assert(elem->rn_refmap->rm_session->rs_cache);

	kmem_cache_free(elem->rn_refmap->rm_session->rs_cache, elem);
}

/**
 * refmap_find_locked() - Find a refmap node given the key and refmap bucket
 * @bkt:        the bucket returned by refmap_rlock() or refmap_wlock()
 * @key:        the key of the item to search for..
 *
 * refmap_find_locked() searches for the given key in the tree specified
 * by the given bucket.  If found, it returns a pointer to the refmap_node,
 * otherwise it returns NULL.
 *
 * The caller must currently hold the bucket lock.
 */
static struct refmap_node *
refmap_find_locked(struct refmap_bkt *bkt, u64 key)
{
	struct refmap_node *this;
	struct rb_node     *node;

	node = bkt->rb_root.rb_node;

	while (node) {
		this = rb_entry(node, struct refmap_node, rn_entry);

		if (key < this->rn_key)
			node = node->rb_left;
		else if (key > this->rn_key)
			node = node->rb_right;
		else
			return this;
	}

	return NULL;
}

enum find_op {
	OBJ_FIND_GET,
	OBJ_FIND,
};

static merr_t
refmap_obj_find_impl(
	struct refmap          *refmap,
	u64                     key,
	u64                    *genp,
	struct refmap_obj      *obj,
	enum find_op            find_op)
{
	struct refmap_node *elem;
	struct refmap_bkt  *bkt;

	refmap_rlock(refmap, key, genp, &bkt);

	elem = refmap_find_locked(bkt, key);
	if (!elem) {
		refmap_runlock(bkt);
		return merr(ENOENT);
	}

	if (find_op == OBJ_FIND_GET)
		atomic_inc(&elem->rn_refcnt);  /* Get a ref on node */

	*obj = elem->rn_obj;  /* Return a copy of the user object */

	refmap_runlock(bkt);

	return 0;
}

merr_t
refmap_obj_find_get(
	struct refmap          *refmap,
	u64                     key,
	u64                    *genp,
	struct refmap_obj      *obj)
{
	return refmap_obj_find_impl(refmap, key, genp, obj, OBJ_FIND_GET);
}

merr_t
refmap_obj_resolve(
	struct refmap          *refmap,
	u64                     key,
	u64                    *genp,
	struct refmap_obj      *obj)
{
	return refmap_obj_find_impl(refmap, key, genp, obj, OBJ_FIND);
}

merr_t
refmap_node_destructor(struct refmap_node *elem)
{
	struct refmap      *refmap;

	if (!elem)
		return 0;

	refmap = elem->rn_refmap;

	if (ev(!RB_EMPTY_NODE(&elem->rn_entry)))
		return merr(EBUSY);

	if (refmap->rm_dtor)
		refmap->rm_dtor(elem, refmap->rm_dtor_arg);

	return 0;
}

/**
 * refmap_obj_find_put_impl() - put an object by key
 *
 * @refmap
 * @key
 * @zap     - if true, this will delete the node regardless of whether
 *            decrementing the refcount made it zero
 *
 * return value:
 *   * for put, the new refcount on the object with that key is returned
 *   * for zap, the "leaked refcount" is returned
 *   * If no such node was found, 0 is returned and an error is logged
 *     (should this be a warning instead?)
 */
static int
refmap_obj_find_put_impl(struct refmap *refmap, u64 key, int zap)
{
	struct refmap_node *elem;
	struct refmap_bkt  *bkt;
	int                 newref;
	bool                emptied = false;

	refmap_wlock(refmap, key, &bkt);
	elem = refmap_find_locked(bkt, key);
	if (!elem) {
		refmap_wunlock(bkt);
		return -1;
	}

	newref = atomic_dec_return(&elem->rn_refcnt);

	if (zap || newref == 0) {
		if (!RB_EMPTY_NODE(&elem->rn_entry)) {
			rb_erase(&elem->rn_entry, &bkt->rb_root);
			++bkt->rb_gen;

			emptied = !bkt->rb_root.rb_node;
		}
	}

	refmap_wunlock(bkt);

	if ((zap || (newref == 0)) && refmap->rm_dtor)
		refmap->rm_dtor(elem, refmap->rm_dtor_arg);

	/* If the bucket became empty, release bucket ref on refmap */
	if (emptied)
		refmap_put(refmap);

	return newref;
}

int
refmap_obj_put(struct refmap *refmap, u64 key)
{
	return refmap_obj_find_put_impl(refmap, key, 0);
}

int
refmap_obj_zap(struct refmap *refmap, u64 key)
{
	return refmap_obj_find_put_impl(refmap, key, 1);
}

merr_t
refmap_insert_locked(struct refmap_bkt *bkt, struct refmap_node *elem)
{
	struct refmap_node *this;
	struct rb_node     *parent;
	struct rb_node    **new;

	new = &bkt->rb_root.rb_node;
	parent = NULL;

	while (*new) {
		this = rb_entry(*new, struct refmap_node, rn_entry);
		parent = *new;

		if (elem->rn_key < this->rn_key)
			new = &((*new)->rb_left);
		else if (elem->rn_key > this->rn_key)
			new = &((*new)->rb_right);
		else
			return merr(EEXIST);

	}

	/* Add new node and rebalance tree.
	 */
	rb_link_node(&elem->rn_entry, parent, new);
	rb_insert_color(&elem->rn_entry, &bkt->rb_root);

	return 0;
}

merr_t
refmap_node_insert(struct refmap_node *elem)
{
	struct refmap_bkt  *bkt;
	bool                empty;
	merr_t              err;

	refmap_wlock(elem->rn_refmap, elem->rn_key, &bkt);
	empty = !bkt->rb_root.rb_node;
	err = refmap_insert_locked(bkt, elem);
	refmap_wunlock(bkt);

	/* If we filled an empty bucket, grab another ref on the refmap */
	if (!err && empty)
		refmap_get(elem->rn_refmap);

	return err;
}

merr_t
refmap_node_insert2(struct refmap_node *elem, u64 gen)
{
	struct refmap_bkt  *bkt;
	bool                empty;
	int                 err = merr(EAGAIN);

	refmap_wlock(elem->rn_refmap, elem->rn_key, &bkt);
	empty = !bkt->rb_root.rb_node;

	if (gen == bkt->rb_gen)
		err = refmap_insert_locked(bkt, elem) ? EEXIST : 0;

	refmap_wunlock(bkt);

	if (ev(err))
		return err;

	if (empty)
		refmap_get(elem->rn_refmap);

	return 0;
}
