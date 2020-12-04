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
    EVENT_LOCKED_INIT((e), \
	.hook = _hook, \
	.data = _data, \
	); \
    (e)->name = #_hook; \
    (e)->file = __FILE__; \
    (e)->line = __LINE__; \
    (e)->default_lock = 1; \
    })

#define ev_setup_unlocked(e, _hook, _data) ({ \
    ev_setup(e, _hook, _data); \
    (e)->default_lock = 0; \
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

/* Schedule the event. */
#ifdef DEBUGGING
void ev_schedule_(event *, const char *, const char *, uint);
#define ev_schedule(e) ev_schedule_(e, #e, __FILE__, __LINE__)
#else
void ev_schedule(event *);
#endif

/* Cancel an event. Set @allow_self=1 to allow self cancellation.
 * Blocks until the event has stopped.
 *
 * You may not cancel every event around there. To be on the safe side,
 * you should:
 *
 * (1) have the event owner locked AND
 * (2) explicitly allow cancellation in the event implementation AND
 * (3) never allocate or free other events from any cancellable event.
 *
 * The cancellation is implemented as domain lock failure.
 * When implementing the cancellable event, you MUST use
 * LOCKED_DO ( cleanup ) when acquiring a domain lock from an unlocked context.
 * These domains are called cancellation-critical.
 * The cancellation requestor MUST ensure that the target event has no of
 * the cancellation-critical domains locked.
 *
 * For more info on the event model, see the documentation.
 * */
enum ev_cancel_result {
  EV_CANCEL_NONE = 0,	  /* The event was not scheduled/running */
  EV_CANCEL_STOPPED = 1,  /* The event has stopped */
  EV_CANCEL_SELF = 2,	  /* Cancelling self, be careful */
} ev_cancel(event *, _Bool allow_self);

/* Dump event info on debug console */
void ev_dump(event *r);

#endif
