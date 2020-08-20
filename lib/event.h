/*
 *	BIRD Library -- Event Processing
 *
 *	(c) 1999-2017 Martin Mares <mj@ucw.cz>
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_EVENT_H_
#define _BIRD_EVENT_H_

#include "lib/locking.h"
#include "lib/resource.h"

#include <stdatomic.h>

typedef struct event {
  resource r;
  LOCKED_STRUCT(event_state, 
      void (*hook)(void *);
      void *data;
      struct coro_event *coro;
    );
  const char *name;
  const char *file;
  uint line;
  _Bool default_lock;
} event;

/* These routines are called from outside */
/* Create a new event */
event *ev_new(pool *);

/* Initialize an event; run only if event is inactive. */
#define ev_setup(e, _hook, _data) ({ \
    EVENT_LOCKED_INIT_LOCK(e); \
    EVENT_LOCKED { \
      AUTO_TYPE eu = UNLOCKED_STRUCT(event_state, e); \
      ASSERT_DIE(eu->coro == NULL); \
      eu->hook = _hook; \
      eu->data = _data; \
    } \
    e->name = #_hook; \
    e->file = __FILE__; \
    e->line = __LINE__; \
    e->default_lock = 1; \
    })

#define ev_setup_unlocked(e, _hook, _data) ({ \
    ev_setup(e, _hook, _data); \
    e->default_lock = 0; \
    })

/* Create and initialize a new event */
#define ev_new_init(p, hook, data) ({ \
    event *e = ev_new(p); \
    ev_setup(e, hook, data); \
    e; })

#define ev_new_init_unlocked(p, hook, data) ({ \
    event *e = ev_new(p); \
    ev_setup_unlocked(e, hook, data); \
    e; })

/* Schedule the event */
#ifdef DEBUGGING
void ev_schedule_(event *, const char *, const char *, uint);
#define ev_schedule(e) ev_schedule_(e, #e, __FILE__, __LINE__)
#else
void ev_schedule(event *);
#endif

/* Cancel an event. Returns 1 if there was an active event running. */
_Bool ev_cancel(event *);

/* Suspend and wait for current locks.
 * This is an explicit cancellation point. */
void ev_suspend(void);

/* Cancellation point check */
_Bool ev_get_cancelled(void);
NORET void ev_exit(void);

/* Dump event info on debug console */
void ev_dump(event *r);

#endif
