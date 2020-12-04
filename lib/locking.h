/*
 *	BIRD Library -- Locking
 *
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LOCKING_H_
#define _BIRD_LOCKING_H_

/* Init on BIRD startup */
void coro_init(void);

/* Locking */
struct domain_generic;

/* Here define the global lock order; first to last. */
#define LOI(type) struct domain_generic *type;
struct lock_order {
  LOI(the_bird);
  LOI(bfd);
  LOI(timer);
  LOI(event_state);
};
#undef LOI

#define LOCK_ORDER_DEPTH  (sizeof(struct lock_order) / sizeof(struct domain_generic *))

extern _Thread_local struct lock_order locking_stack;
extern _Thread_local struct domain_generic **last_locked;

/* Internal for locking */
USE_RESULT _Bool do_lock(struct domain_generic *dg, struct domain_generic **lsp);
void do_unlock(struct domain_generic *dg, struct domain_generic **lsp);

#define DOMAIN(type) struct domain__##type
#define DEFINE_DOMAIN(type) DOMAIN(type) { struct domain_generic *type; }

#define DOMAIN_NEW(type, name)  (DOMAIN(type)) { .type = domain_new(name) }
struct domain_generic *domain_new(const char *name);

#define DOMAIN_FREE_AFTER_UNLOCK(type, d) ({ \
    ASSERT_LOCK(type, d); \
    domain_free_after_unlock((d).type); \
    })
void domain_free_after_unlock(struct domain_generic *dg);

#define DOMAIN_NULL(type)   (DOMAIN(type)) {}

/* Pass a locked context to a subfunction */
#define LOCKED(type) DOMAIN(type) _bird_current_lock
#define CURRENT_LOCK _bird_current_lock
#define IS_LOCKED(type)  (last_locked - &locking_stack.type >= 0) && locking_stack.type
#define ASSERT_LOCK(type, d) ASSERT_DIE(IS_LOCKED(type) && _bird_current_lock.type == (d).type)

#define SUPER_LOCK(type)  ({ ASSERT_DIE(IS_LOCKED(type)); (DOMAIN(type)) { .type = locking_stack.type }; })

/* Uncoupled lock/unlock, don't use directly */
#define LOCK_DOMAIN(type, d)	LOCKED(type) = (do_lock(((d).type), &(locking_stack.type)) ? (d) : (DOMAIN(type)) {})
#define UNLOCK_DOMAIN(type, d)  do_unlock(((d).type), &(locking_stack.type))

/* Do something in a locked context; run cleanup if unsuccessful */
#define LOCKED_DO(type, d, cleanup) for ( \
    LOCK_DOMAIN(type, d), _bird_aux = (d); \
    CURRENT_LOCK.type ? (_bird_aux.type ? ((_bird_aux.type = NULL), 1) : 0) : ((cleanup), 0); \
    UNLOCK_DOMAIN(type, d))

#define LOCKED_DO_NOFAIL(type, d) LOCKED_DO(type, d, bug("Invalid cancellation at %s:%d", __FILE__, __LINE__))

/* Part of struct that should be accessed only with a locked lock */
#define LOCKED_STRUCT(lock_type, ...) struct { \
  __VA_ARGS__ \
  DOMAIN(lock_type) _lock; \
} LOCKED_STRUCT_NAME(lock_type)

#define LOCKED_STRUCT_INIT_LOCK(lock_type, parent, domain) ({ \
    AUTO_TYPE _str = &(parent)->LOCKED_STRUCT_NAME(lock_type); \
    ASSERT_DIE(!_str->_lock.lock_type); \
    _str->_lock = domain; \
    })

/* Locked struct accessor */
#define UNLOCKED_STRUCT(lock_type, parent) ({ \
    AUTO_TYPE _ustr = &(parent)->LOCKED_STRUCT_NAME(lock_type); \
    ASSERT_LOCK(lock_type, _ustr->_lock); \
    _ustr; })

/* Lock, get single item, unlock */
#define LOCKED_GET(type, str, d, var) ({ \
    AUTO_TYPE _str = str; \
    typeof(_str->LOCKED_STRUCT_NAME(type).var) _out; \
    LOCKED_DO(type, d) _out = UNLOCKED_STRUCT(type, _str)->var; \
    _out; })

/* Lock, set single item, unlock */
#define LOCKED_SET(type, str, d, var, val) ({ \
    LOCKED_DO(type, d) UNLOCKED_STRUCT(type, str)->var = val; \
    })

/* Locked struct initializer with no locking involved */
#define LOCKED_STRUCT_INIT(lock_type, parent, domain, ...) ({ \
    AUTO_TYPE _str = &(parent)->LOCKED_STRUCT_NAME(lock_type); \
    *_str = (typeof(*_str)) { ._lock = domain, __VA_ARGS__ }; \
    })

#define LOCKED_STRUCT_NAME(lock_type) domain_locked__##lock_type

/* Break from the locked context */
#define LOCKED_BREAK  continue

/* Lock, get value, unlock, return */
#define LOCKED_RETURN(type, d, expr) return ({ \
    LOCK_DOMAIN(type, d); \
    AUTO_TYPE _ret = expr; \
    UNLOCK_DOMAIN(type, d); \
    _ret; \
    })


DEFINE_DOMAIN(event_state);
extern DOMAIN(event_state) event_state_domain;

#define EVENT_LOCKED(cancel) LOCKED_DO(event_state, event_state_domain, cancel)
#define EVENT_LOCKED_NOFAIL LOCKED_DO_NOFAIL(event_state, event_state_domain)
#define EVENT_LOCKED_INIT(str, ...) LOCKED_STRUCT_INIT(event_state, str, event_state_domain, __VA_ARGS__)
#define EVENT_LOCKED_INIT_LOCK(str) LOCKED_STRUCT_INIT_LOCK(event_state, str, event_state_domain)

/* Use with care. To be removed in near future. */
DEFINE_DOMAIN(the_bird);
extern DOMAIN(the_bird) the_bird_domain;

#define the_bird_lock()		do_lock(the_bird_domain.the_bird, &locking_stack.the_bird)
#define the_bird_unlock()	do_unlock(the_bird_domain.the_bird, &locking_stack.the_bird)

#define THE_BIRD_LOCKED(cleanup)  LOCKED_DO(the_bird, the_bird_domain, cleanup)

#define assert_bird_lock() ASSERT_DIE(SUPER_LOCK(the_bird).the_bird == the_bird_domain.the_bird)

#endif
