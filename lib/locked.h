/*
 *	BIRD Library -- Locked data structures
 *
 *	(c) 2019 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LOCKED_H_
#define _BIRD_LOCKED_H_

#include "lib/atomic.h"
#include "lib/lists.h"

typedef _Atomic u64 spinlock;

/* Exporting worker ID for spinlock use */
#define NOWORKER (~((u64) 0))
extern _Thread_local u64 worker_id;

#define SPIN_LOCK(_sp) do { \
  while (1) { \
    u64 noworker = NOWORKER; \
    if (atomic_compare_exchange_weak_explicit(&_sp, &noworker, worker_id, memory_order_acquire, memory_order_relaxed)) \
      break; \
    CPU_RELAX(); \
  } \
} while (0)

#define SPIN_UNLOCK(_sp) do { \
  u64 expected = worker_id; \
  if (!atomic_compare_exchange_strong_explicit(&_sp, &expected, NOWORKER, memory_order_release, memory_order_relaxed)) \
    bug("The spinlock is locked by worker %lu but shall be locked by %lu!", expected, worker_id); \
} while (0)

#define SPIN_INIT(_sp) atomic_store_explicit(&(_sp), NOWORKER, memory_order_relaxed);

/* Locked typed linked list */

#define LOCKED_LIST(_type) struct { \
  TLIST(_type) _llist; \
  spinlock _lsp; \
}

#define LOCKED_LIST_NODE(_type) struct { \
  TLIST_NODE(_type); \
  spinlock *_lsp; \
}

#define INIT_LOCKED_LIST(list_) do { \
  INIT_TLIST(&((list_)->_llist)); \
  SPIN_INIT(((list_)->_lsp)); \
} while (0)

#define NODE_IN_LOCKED_LIST(node_) (!!((node_)->_lsp))

#define LOCKED_LIST_LOCK(list_, token) do { typeof(&((list_)->_llist)) token = &((list_)->_llist); SPIN_LOCK((list_)->_lsp); do
#define LOCKED_LIST_UNLOCK(list_) while (0); SPIN_UNLOCK((list_)->_lsp); } while (0)

#define GET_HEAD_LOCKED(list_) ({ \
    TLIST_NODE_TYPE(&((list_)->_llist)) *node_ = NULL; \
    SPIN_LOCK((list_)->_lsp); \
    if (!TLIST_EMPTY(&((list_)->_llist))) \
      node_ = THEAD(&((list_)->_llist)); \
    SPIN_UNLOCK((list_)->_lsp); \
    node_; \
    })

#define ADD_HEAD_LOCKED(list_, node_) do { \
  node_->_lsp = &((list_)->_lsp); \
  SPIN_LOCK((list_)->_lsp); \
  TADD_HEAD(&((list_)->_llist), node_); \
  SPIN_UNLOCK((list_)->_lsp); \
} while (0)

#define ADD_TAIL_LOCKED(list_, node_) do { \
  (node_)->_lsp = &((list_)->_lsp); \
  SPIN_LOCK((list_)->_lsp); \
  TADD_TAIL(&((list_)->_llist), node_); \
  SPIN_UNLOCK((list_)->_lsp); \
} while (0)

#define REM_HEAD_LOCKED(list_) ({ \
    TLIST_NODE_TYPE(&((list_)->_llist)) *node_ = NULL; \
    SPIN_LOCK((list_)->_lsp); \
    if (!TLIST_EMPTY(&((list_)->_llist))) { \
      node_ = THEAD(&((list_)->_llist)); \
      TREM_NODE(node_); \
    } \
    SPIN_UNLOCK((list_)->_lsp); \
    if (node_) node_->_lsp = NULL; \
    node_; \
    })

#define REM_NODE_LOCKED(node_) do { \
  SPIN_LOCK(*(node_->_lsp)); \
  TREM_NODE(node_); \
  SPIN_UNLOCK(*(node_->_lsp)); \
  node_->_lsp = NULL; \
} while (0)

#endif