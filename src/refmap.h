/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_REFMAP_H
#define MPOOL_REFMAP_H

/**
 * DOC: refmap facility implementation notes.
 *
 * The refmap facility provides an unordered map for which a reference count
 * is maintained on each key/value pair being held in the map.  It supports
 * typical map operations (e.g, insert, delete, find, ...) with the constraint
 * that a find operation returns a value that is referenced such that the
 * key/value pair cannot be deleted from the map until all such references
 * are released.
 *
 * The primary use case for refmap is to provide fast cached access to
 * an underlying resource that is expensive to acquire and/or to provide
 * reference counted management of a resource that does not instrinsically
 * provide it.
 *
 * refmap is implemented as a shrub (i.e., a small hash table of red-black
 * trees).  It is fixed in size for use in the kernel such that it efficiently
 * uses at most one 4KB page worth of memory for the base refmap data structure.
 * refmap nodes are by default 64-bytes each, but that may be extended on a
 * per session basis.  The implementation provides an API to allocate and
 * free refmap nodes, also allows the user to embed them in private structures
 * and hence manage the refmap nodes outside of the refmap facility.
 *
 * The following pseudo-code outlines the general order of calls required
 * to use the refmap facility.
 *
 * struct refmap_session *session;
 * struct remap_node *ref, *dup;
 * struct refmap *map;
 * merr_t err;
 *
 * 1) Create a refmap session:
 *        refmap_session_create("myrefmap", 0, &session);
 *
 * 2) Create one or more refmaps in our session:
 *        refmap_create(session, NULL, &map);
 *
 * 3) Create a refmap node and insert it into the refmap:
 *        ref = refmap_node_alloc(map, key, value);
 *        dup = refmap_node_insert(ref);
 *        if (dup) {
 *            refmap_obj_put(ref);
 *            ref = dup;
 *        }
 *
 * 4) Release the refmap node when done using it:
 *        refmap_obj_put(ref);
 *
 * 5) Search for a particular key/value pair, and get the value payload:
 *        err = refmap_obj_find_get(map, key, &gen, &obj); (gets a ref on node)
 *        err = refmap_obj_find(map, key, &gen, &obj);     (no new ref on node)
 *
 * 6) Delete a refmap node:
 *        err = refmap_node_delete(ref);
 *        refmap_obj_put(ref);
 *
 * 7) Release one or more refmaps:
 *        refmap_drop(map);
 *        refmap_put(map);
 *
 * 8) Repeat 2, 3, 4, 5, 6 and/or 7 ad nauseam to various effect..
 *
 * 9) Terminate the refmap session (after destroy all refmaps)
 *        refmap_session_put(session);
 *
 * Refcounting in refmaps
 *
 * * Each refmap holds a refcount on the refmap_session
 * * Each non-empty bucket in a refmap holds a refcount on the refmap
 * * Each refmap object may have caller/client refs on it; objects should
 *   not be removed if they have references.  If a caller knows what they're
 *   doing and wants to do this, refmap_obj_zap() will do it.
 */


/**
 * DOC: REFMAP_BKT_MAX
 *
 * The maximum number of buckets in a refmap hash table.  Due to the simplistic
 * hash function (see refmap_key_to_bktidx()) it must be prime in order to avoid
 * poor distribution caused by keys which have factors in common with the table
 * size.  It is also chosen to maximize the number of buckets in one 4KB page.
 * If you change this be sure to adjust the alignment of struct refmap.
 */
#define REFMAP_BKT_MAX      (61)

struct refmap_node;

typedef void refmap_dtor_t(struct refmap_node *elem, void *arg);

/**
 * struct refmap_session - contains the root of one rb-tree and associated lock
 * @rs_cache:   pointer to a kmem cache
 * @fs_refcnt:  number of active references to this session
 * @rs_name:    session name
 * @rs_size:    additional amount to allocate to each refmap_node
 *
 * Created by refmap_session_create().
 *
 * At a minimum, the caller of refmap_session_create() holds a reference
 * to a session which must be released by calling refmap_session_put()
 * when the caller no longer needs the session.  Additionally, each call
 * to refmap_create() acquires a reference to the given session which
 * is released automatically when the refmap refeerence count drops
 * to zero.
 */
struct refmap_session {
	struct kmem_cache  *rs_cache;
	atomic_t            rs_refcnt;
	const char         *rs_name;
	size_t              rs_size;
};

/**
 * struct refmap_bkt - contains the root of one rb-tree and associated lock
 * @rb_lock:    used to lock access to rb_root and rb_gen
 * @rb_root:    rb-tree root node
 * @rb_gen:     generation count (increments whenever a node is deleted)
 */
struct refmap_bkt {
	struct rw_semaphore rb_lock;
	struct rb_root      rb_root;
	u64                 rb_gen;
} __aligned(64);

struct refmap {
	struct refmap_bkt       rm_bktv[REFMAP_BKT_MAX];
	struct refmap_session  *rm_session;
	refmap_dtor_t          *rm_dtor;
	void                   *rm_dtor_arg;
	atomic_t                rm_refcnt;
} __aligned(4096);

/**
 * struct refmap_obj - a user object which is stored in a refmap_node.
 *
 * This is the user payload in a refmao_node.  The fields are opaque to
 * the refmap code.
 */
struct refmap_obj {
	u64             ro_priv1;
	void           *ro_value;
};

/**
 * struct refmap_node - a refmap node which maps a key to a ref counted value
 * @rn_key:     rb-tree search key
 * @rn_entry:   rb-tree entry
 * @rn_refmap:  pointer to containing refmap
 * @rn_flags:   REFMAP_* flags
 * @rn_refcnt:  node reference count
 * @rn_obj:     the user data
 */
struct refmap_node {
	u64               rn_key;
	struct rb_node    rn_entry;
	u32               rn_flags;
	atomic_t          rn_refcnt;
	struct refmap    *rn_refmap;
	struct refmap_obj rn_obj;
};

/**
 * refmap_session_create() - Create a refmap session
 * @name:       session name
 * @size:       additional refmap node size
 * @sessionp:   pointer to session pointer
 *
 * refmap_session_create() creates and initializes a refmap session and
 * returns a pointer to it.  The size parameter is used to request an
 * additional number of bytes to allocate to the refmap node above and
 * beyond it's defined size for private use by the caller.
 */
merr_t
refmap_session_create(
	const char             *name,
	size_t                  size,
	struct refmap_session **sessionp);


/**
 * refmap_session_put() - Release a reference on an refmap session
 * @session:    session pointer obtained from refmap_session_create()
 *
 * refmap_session_put() releases the callers's reference such that
 * the session object will be destroyed once the session reference
 * count reaches zero.  Each call to refmap_create() acquires an
 * additional reference on the given session such that the session
 * will not be destroyed while there are active refmaps using it.
 *
 * Note:  The owner of the session may call refmap_session_put()
 * exactly once.
 */
void refmap_session_put(struct refmap_session *session);


/**
 * refmap_create() - Create a key/value map
 * @session:    session pointer from refmap_session_create()
 * @dtor:       destructor to call when releasing refmap nodes
 * @dtor_arg:   Argument to pass to destructor, along with the element
 * @refmapp:    pointer to a refmap pointer
 *
 * refmap_create() create a refmap and returns a pointer to it via *refmapp.
 * A destructor may be specified, in which case it will be called for
 * each refmap node whose reference count reaches zero.  If a destructor
 * is specified, it is the destructor's responsibility to dispose of the
 * node, thereby allowing the caller to embed refmap node objects within
 * a private structure.
 */
merr_t
refmap_create(
	struct refmap_session  *session,
	refmap_dtor_t          *dtor,
	void                   *dtor_arg,
	struct refmap         **refmapp);


/**
 * refmap_put() - Release a reference on a refmap
 * @refmap:     key/value map pointer
 *
 * refmap_put() releases the caller's reference such that the refmap will
 * be destroyed when the reference count reaches zero.  Each non-empty
 * bucket in the refmap acquires a reference on the refmap such that
 * the refmap will not be destroyed while it contains refmap nodes.
 *
 * Note: The owner of the refmap may call refmap_put() exactly once.
 */
void refmap_put(struct refmap *refmap);


/**
 * refmap_drop() - Purge the refmap cache of all idle refmap nodes
 * @refmap:     key/value map pointer
 * @nodes:      pointer to count of refmap nodes that were purged
 *              (i.e. nodes that had not been put)
 * @refs:       total refcount on @nodes
 *
 * refmap_drop() scans the given refmap and removes all idle refmap nodes
 * from the map (i.e., nodes with a reference count of 1).  It may safely
 * be called at any time, but must be called prior to the final refmap_put()
 * when the refmap is no longer needed.
 */
void refmap_drop(struct refmap  *refmap, int *nodes, int *refs);

/**
 * refmap_rlock() - Lock a refmap bucket for shared access
 * @key:        key of item used to locate bucket
 * @genp:       bucket generation count
 * @bktp:       pointer to locked bucket
 *
 * refmap_rlock() locks for shared/read-only access the bucket that would
 * contain the given key.  It returns the current bucket generation count
 * and a pointer to the bucket in *genp and *bktp, respectively.  The
 * locked bucket may then be passed to refmap functions whose name end
 * with the "_locked" suffix.
 */
void
refmap_rlock(
	struct refmap      *refmap,
	u64                 key,
	u64                *genp,
	struct refmap_bkt **bktp);


/**
 * refmap_runlock() - Unlock the given refmap bucket
 * @bkt:        the bucket to unlock
 *
 * Caller must hold the bucket lock acquired via refmap_rlock().
 */
void refmap_runlock(struct refmap_bkt *bkt);


/**
 * refmap_wlock() - Lock a refmap bucket for exclusive access
 * @key:        key of item used to locate bucket
 * @bktp:       pointer to locked bucket
 *
 * Same as refmap_rlock(), but locks the bucket for exclusive/read-write access.
 */
void refmap_wlock(struct refmap *refmap, u64 key, struct refmap_bkt **bktp);


/**
 * refmap_wunlock() - Unlock the given refmap bucket
 * @bkt:        the bucket to unlock
 *
 * Caller must hold the bucket lock acquired via refmap_wlock().
 */
void refmap_wunlock(struct refmap_bkt *bkt);


/**
 * refmap_node_alloc() - Allocate and initialize a refmap node
 * key:     unique key for the node
 * value:   value pointer
 *
 * refmap_node_alloc() allocates and initializes a refmap node with the
 * given parameters.  The caller should dispose of the node by calling
 * refmap_obj_put(), unless a destructor was given to
 * refmap_session_create(), in which case the custom destructor should
 * call refmap_node_free() to dispose of the node.
 */
struct refmap_node *
refmap_node_alloc(
	struct refmap  *refmap,
	u64             key,
	void           *value,
	u64             priv1);

/**
 * refmap_node_free() - Free a refmap node
 * @elem:       a refmap node allocated via refmap_node_alloc()
 *
 * Returns the given node to the default memory mpoo.  Should only
 * be called by a custom destructor specified at refmap creation.
 */
void refmap_node_free(struct refmap_node *elem, void *arg);

/**
 * refmap_node_destructor() - Call the destructor for a refmap node that is
 *                            not in its refmap.
 *
 * @elem  - The element to be destroyed
 */
merr_t refmap_node_destructor(struct refmap_node *elem);

/**
 * refmap_obj_put() - Release a reference on the given refmap node
 *
 * @refmap
 * @key:       The key for the refmap node to be put
 *
 * refmap_obj_put() releases the caller's reference on the given node.
 * If the rn_refcnt goes to 0:
 *   - The node is removed from the appropriate rbtree IF IT'S IN A TREE
 *     (this is required to succeed even if the node is not in an rbtree)
 *   - The refmap destructor is called for the node
 *
 * Returns: the node refcount after the put.  If 0, the node has been
 * removed from the refmap
 */
int refmap_obj_put(struct refmap *refmap, u64 key);

/**
 * refmap_obj_zap() - Release all references on the given refmap node
 *
 * @refmap
 * @key:       The key for the refmap node to be put
 *
 * NOTE: this is a temporary function until we expose APIs and enforce
 * balanced gets/puts from user space callers.
 *
 * This is the same as refmap_obj_put(), except that refmap_obj_zap()
 * always leaves the refcnt at zero, barring a concurrent get.
 *
 * Returns: the number of leaked refs (not counting one for the zapper)
 */
int refmap_obj_zap(struct refmap *refmap, u64 key);


/**
 * refmap_obj_find_get() - Find a refmap node given the key and refmap
 * @refmap:     the k/v map
 * @key:        unique key of the item to find
 * @genp:       pointer to bucket generation count pointer
 * @obj:        pointer to place to store user obj
 *
 * refmap_obj_find_get() searches the refmap for a node with the given key.  If
 * found, a copy of the user object is returned in *obj.  The reference
 * count is incremented on the node.  The caller must call refmap_obj_put()
 * on the key when finished in order to release this reference.
 *
 * Returns 0 if the node was found.
 * Returns ENOENT if the node was not found.
 * Returns EBUSY if the node was found but is marked for removal.
 */
merr_t
refmap_obj_find_get(
	struct refmap          *refmap,
	u64                     key,
	u64                    *genp,
	struct refmap_obj      *obj);


/**
 * refmap_obj_resolve() - Find a refmap node given the key and refmap
 * @refmap:     the k/v map
 * @key:        unique key of the item to find
 * @genp:       pointer to bucket generation count pointer
 * @obj:        pointer to place to store user obj
 *
 * refmap_obj_resolve() searches the refmap for a node with the given key.  If
 * found, a copy of the user object is returned in *obj.  The reference
 * count is NOT incremented on the node (you must already have a ref to call
 * this function).
 *
 * Returns 0 if the node was found.
 * Returns ENOENT if the node was not found.
 * Returns EBUSY if the node was found but is marked for removal.
 */
merr_t
refmap_obj_resolve(
	struct refmap          *refmap,
	u64                     key,
	u64                    *genp,
	struct refmap_obj      *obj);


/**
 * refmap_insert_locked() - Insert the given refmap element into the bucket
 * @bkt:        the bucket returned by refmap_rlock() or refmap_wlock()
 * @elem:       pointer to refmap node
 *
 */
merr_t refmap_insert_locked(struct refmap_bkt *bkt, struct refmap_node *elem);


/**
 * refmap_node_insert() - Insert the given refmap element into the refmap
 * @elem:       pointer to a refmap node
 *
 */
merr_t refmap_node_insert(struct refmap_node *elem);


/**
 * refmap_node_insert2() - Insert the given refmap element into the refmap
 * @elem:       pointer to a refmap node
 * @gen:        generation count returned from a failed find operation
 *
 * refmap_node_insert2() inserts the given element into the refmap only
 * if the bucket generation hasn't changed and there is not already
 * a node in the tree by the given key.
 *
 * The bucket generation count is used to address an obscure race
 * in which there are at least two threads competing to install a
 * reference to the same (likely non-refcounted) object into the
 * refmap.  If both threads acquire a reference to the same object
 * at the same time, but one thread manages to insert a refmap node,
 * destroy the object, then delete the refmap node before the other
 * thread has a chance to run, then the latter thread could install
 * a new refmap node with the now stale object reference.  Use of
 * the generation count detects the above scenario and advises (via
 * EAGAIN) the latter thread to repeat the object acquisition and
 * try again.
 *
 * Returns 0 if the node was successfully inserted.
 * Returns EEXIST if the given key is already in the refmap.
 * Returns EAGAIN if the given generation count is stale.
 */
merr_t refmap_node_insert2(struct refmap_node *elem, u64 gen);

#endif
